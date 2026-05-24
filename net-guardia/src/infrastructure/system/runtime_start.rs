use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use macros::log;
use sd_notify::NotifyState;
use tokio::sync::Semaphore;
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::mpsc::{self, Sender};
use tokio::time::interval;

use crate::adapter::model_change_source::NotifyModelChangeSource;
use crate::adapter::model_loading::config_loader::FsModelConfigLoader;
use crate::adapter::suricata_monitor::SuricataMonitor;
use crate::common::error::Error;
use crate::common::error::system::SystemError;
use crate::common::log::reporting::ReportingLog;
use crate::common::log::system::SystemLog;
use crate::core::correlation::engine::CorrelationEngine;
use crate::core::detection::beaconing::BeaconingDetector;
use crate::core::detection::orchestrator::DetectionOrchestrator;
use crate::core::detection::orchestrator::{bridge_ml_to_detection, bridge_ml_to_flow_observation};
use crate::core::inference::drift_detector::run_drift_monitor;
use crate::core::inference::model_watcher::ModelWatcher;
use crate::core::reporting::stats_aggregator::StatsAggregator;
use crate::domain::common::event::DetectionEvent;
use crate::domain::common::system::health::EbpfHealth;
use crate::domain::detection::flow_observation::FlowObservation;
use crate::domain::detection::log::MLLog;
use crate::domain::detection::model_files::{MODELS_DIR, STAGING_SUBDIR};
use crate::domain::response::log::SoarLog;
use crate::infrastructure::audit_logger::AuditLogger;
use crate::infrastructure::http_runtime::{ForceHttpsFlag, ReadyFlag, SetupCompleteFlag};
use crate::infrastructure::http_server::{self, HttpServerParams};
use crate::infrastructure::staging_cleanup;
use crate::infrastructure::startup::{self, SystemRuntime};
use crate::infrastructure::system::{ShutdownHandle, ShutdownMode, System};
use crate::interface::data_plane::packet_sink::PacketSinkFactory;
use crate::interface::reporting::report_snapshot::ReportSnapshotRepo;
use crate::interface::reporting::stats::StatsRepo;
use crate::interface::system::audit::AuditRepo;
use crate::interface::system::health_query::HealthQuery;

pub async fn start_data_plane(system: &mut System) -> Result<(), Error> {
    let runtime = system.runtime_mut()?;
    if let (Some(ingress), Some(egress)) = (
        runtime.data_plane.ingress_ebpf.as_mut(),
        runtime.data_plane.egress_ebpf.as_mut(),
    ) {
        if startup::data_plane::aya_log_init(ingress, egress).is_err() {
            log!(SystemLog::EbpfBringupFailed);
        }
        attach_ebpf(runtime)?;
    }

    let sink_factory: Arc<dyn PacketSinkFactory> = runtime.detection.inference_runtime.ml_engine.clone();
    if runtime
        .data_plane
        .ebpf_services
        .clone()
        .run(sink_factory)
        .await
        .is_err()
    {
        log!(SystemLog::EbpfBringupFailed);
        runtime.foundation.ebpf_health.store(Arc::new(EbpfHealth::Unavailable));
    }

    runtime
        .foundation
        .readiness
        .ebpf_attached
        .store(runtime.data_plane.ingress_ebpf.is_some(), Ordering::SeqCst);
    Ok(())
}

pub async fn start_inference(system: &System) -> Result<(), Error> {
    let runtime = system.runtime()?;
    runtime.detection.inference_runtime.run().await?;
    runtime.foundation.readiness.ml_model_loaded.store(
        runtime.detection.inference_runtime.ml_inference.is_active(),
        Ordering::SeqCst,
    );
    Ok(())
}

pub async fn start_response(system: &mut System) -> Result<(), Error> {
    let rate_limit_owner_runner;
    let soar_engine;
    let mut threat_rx;
    let readiness;
    let ttl_scheduler;
    {
        let runtime = system.runtime_mut()?;
        runtime.response.soar_engine.recover_active_blocks().await?;
        rate_limit_owner_runner = runtime.response.rate_limit_owner_runner.take();
        soar_engine = runtime.response.soar_engine.clone();
        threat_rx = runtime.foundation.channels.threat_tx.subscribe();
        readiness = runtime.foundation.readiness.clone();
        ttl_scheduler = runtime.response.ttl_scheduler.take();
    }

    if let Some(runner) = rate_limit_owner_runner {
        system.lifecycle.spawn("rate_limit_owner_runner", async move {
            runner.run().await;
        });
    }
    system.lifecycle.spawn("soar_threat_consumer", async move {
        log!(SoarLog::EngineStarted);
        let semaphore = Arc::new(Semaphore::new(soar_engine.handle_concurrency()));
        loop {
            match threat_rx.recv().await {
                Ok(event) => {
                    let permit = match Arc::clone(&semaphore).acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => break,
                    };
                    let engine = Arc::clone(&soar_engine);
                    tokio::spawn(async move {
                        if let Err(e) = engine.handle_threat_event(&event).await {
                            log!(SoarLog::ThreatEventHandlingFailed(e.to_string()));
                        }
                        drop(permit);
                    });
                }
                Err(RecvError::Lagged(n)) => {
                    log!(SoarLog::ReceiverLagged(n));
                }
                Err(RecvError::Closed) => {
                    log!(SoarLog::ChannelClosed);
                    break;
                }
            }
        }
    });
    readiness.soar_engine_running.store(true, Ordering::SeqCst);

    if let Some(ttl) = ttl_scheduler {
        system.lifecycle.spawn("ttl_scheduler", async move {
            log!(SoarLog::TtlSchedulerStarted);
            let mut interval = interval(Duration::from_secs(60));
            interval.tick().await;
            loop {
                interval.tick().await;
                if let Err(e) = ttl.sweep().await {
                    log!(SoarLog::TtlSweepFailed(e.to_string()));
                }
            }
        });
    }

    Ok(())
}

pub fn start_detection_graph(system: &mut System) -> Result<Sender<DetectionEvent>, Error> {
    let (
        app_config,
        threat_tx,
        audit_tx,
        geoip,
        fusion_metrics,
        ml_detection_rx,
        ml_flow_observation_rx,
        ml_inference,
        model_runtime_loader,
        model_artifact_resolver,
        inference_features,
        attack_types,
        model_status,
    ) = {
        let runtime = system.runtime()?;
        (
            runtime.foundation.app_config.clone(),
            runtime.foundation.channels.threat_tx.clone(),
            runtime.foundation.channels.audit_tx.clone(),
            runtime.response.geoip.clone(),
            runtime.detection.inference_runtime.fusion_metrics.clone(),
            runtime.detection.inference_runtime.ml_alert.subscribe_to_alerts(),
            runtime.detection.inference_runtime.ml_alert.subscribe_to_alerts(),
            runtime.detection.inference_runtime.ml_inference.clone(),
            runtime.detection.inference_runtime.model_runtime_loader.clone(),
            runtime.detection.inference_runtime.model_artifact_resolver.clone(),
            runtime.detection.inference_config.num_ae_features(),
            runtime.detection.inference_runtime.ml_inference.attack_type_count(),
            runtime.detection.inference_runtime.ml_inference.model_source_status(),
        )
    };
    let (flow_observation_tx, _) = broadcast::channel::<FlowObservation>(1024);

    let (detection_tx, detection_rx) = mpsc::channel::<DetectionEvent>(1024);
    let orchestrator =
        DetectionOrchestrator::new(&app_config, detection_rx, threat_tx, audit_tx, geoip, fusion_metrics);
    system.lifecycle.spawn("detection_orchestrator", async move {
        orchestrator.run().await;
    });

    let correlation_engine = CorrelationEngine::new(&app_config, flow_observation_tx.subscribe(), detection_tx.clone());
    system.lifecycle.spawn("correlation_engine", async move {
        correlation_engine.run().await;
    });

    let beaconing_detector = BeaconingDetector::new(&app_config, flow_observation_tx.subscribe(), detection_tx.clone());
    system.lifecycle.spawn("beaconing_detector", async move {
        beaconing_detector.run().await;
    });

    let suricata_detection_tx = detection_tx.clone();

    system.lifecycle.spawn(
        "ml_flow_observation_bridge",
        bridge_ml_to_flow_observation(ml_flow_observation_rx, flow_observation_tx),
    );
    system.lifecycle.spawn(
        "ml_detection_bridge",
        bridge_ml_to_detection(ml_detection_rx, detection_tx),
    );

    let staging_root = PathBuf::from(MODELS_DIR).join(STAGING_SUBDIR);
    match staging_cleanup::clean_staging_orphans(&staging_root, Duration::from_secs(3600)) {
        Ok(0) => {}
        Ok(n) => log!(MLLog::StagingOrphansCleaned(n as u64)),
        Err(e) => log!(MLLog::StagingOrphansSweepFailed(e.to_string())),
    }

    match serde_json::to_string(&model_status) {
        Ok(s) => log!(MLLog::ModelStatusSummary(s)),
        Err(e) => log!(MLLog::ModelStatusSummary(format!("<unserializable status: {e}>"))),
    }
    log!(MLLog::ConfigLoaded(inference_features, attack_types,));

    let model_watcher = ModelWatcher::new(
        ml_inference,
        app_config,
        model_runtime_loader,
        model_artifact_resolver,
        Arc::new(NotifyModelChangeSource::new(PathBuf::from(MODELS_DIR))),
        Arc::new(FsModelConfigLoader),
    );
    system.lifecycle.spawn("model_watcher", async move {
        if let Err(e) = model_watcher.run().await {
            log!(MLLog::InferenceFailed(
                "ModelWatcher".to_string(),
                format!("watcher failed to start: {e}"),
            ));
        }
    });

    Ok(suricata_detection_tx)
}

pub async fn start_observability(system: &mut System) -> Result<(), Error> {
    let health;
    let database;
    let audit_rx;
    let drift_rx;
    let drift_detector;
    let drift_tx;
    let report_scheduler;
    let monitoring_interval_secs;
    {
        let runtime = system.runtime_mut()?;
        monitoring_interval_secs = runtime.foundation.app_config.load().health.monitoring_interval_secs;
        health = runtime.observability.health.clone();
        database = runtime.foundation.database.clone();
        audit_rx = runtime.foundation.channels.audit_tx.subscribe();
        drift_rx = runtime.foundation.channels.drift_tx.subscribe();
        drift_detector = runtime.detection.drift_detector.clone();
        drift_tx = runtime.foundation.channels.drift_tx.clone();
        report_scheduler = runtime.reporting.report_scheduler.take();
    }

    let (health_shutdown, health_handle) = health.clone().run(Duration::from_secs(monitoring_interval_secs)).await;
    system
        .lifecycle
        .graceful("system_health", health_shutdown, health_handle);

    let audit_logger = Arc::new(AuditLogger::new(database.clone() as Arc<dyn AuditRepo>));
    for (name, handle) in audit_logger.start(audit_rx, drift_rx) {
        system.lifecycle.track(name, handle);
    }

    let health_query: Arc<dyn HealthQuery> = health;
    let stats_aggregator = StatsAggregator::new(
        database.clone() as Arc<dyn StatsRepo>,
        database as Arc<dyn ReportSnapshotRepo>,
        health_query,
    );
    system.lifecycle.spawn("stats_aggregator", async move {
        log!(ReportingLog::StatsAggregatorStarted);
        if let Err(e) = stats_aggregator.aggregate().await {
            log!(ReportingLog::InitialStatsAggregationFailed(e.to_string()));
        }
        let mut interval = interval(Duration::from_secs(3600));
        interval.tick().await;
        loop {
            interval.tick().await;
            if let Err(e) = stats_aggregator.aggregate().await {
                log!(ReportingLog::StatsAggregationFailed(e.to_string()));
            }
        }
    });

    if let Some(runner) = system.runtime_mut()?.detection.drift_detector_runner.take() {
        system.lifecycle.spawn("drift_detector_runner", async move {
            runner.run().await;
        });
    }
    system.lifecycle.spawn("drift_monitor", async move {
        run_drift_monitor(drift_detector, drift_tx).await;
    });

    if let Some(report) = report_scheduler {
        system.lifecycle.spawn("report_scheduler", async move {
            log!(ReportingLog::WeeklyReportSchedulerStarted);
            let mut interval = interval(Duration::from_secs(3600));
            interval.tick().await;
            loop {
                interval.tick().await;
                report.send_if_due().await;
            }
        });
    }
    Ok(())
}

pub async fn start_http(system: &mut System) -> Result<mpsc::Receiver<ShutdownMode>, Error> {
    let force_https = ForceHttpsFlag(Arc::new(AtomicBool::new(
        system.runtime()?.foundation.app_config.load().http_server.force_https,
    )));

    let (shutdown_tx, shutdown_rx) = mpsc::channel::<ShutdownMode>(1);
    let shutdown_handle = Arc::new(ShutdownHandle::new(shutdown_tx));
    system.shutdown_handle = Some(shutdown_handle.clone());

    let ready_flag = ReadyFlag(Arc::new(AtomicBool::new(false)));
    let ready_flag_for_set = ready_flag.0.clone();
    let logger = system.runtime()?.foundation.logger.clone();
    let log_buffer = system.runtime()?.foundation.log_buffer.clone();
    let params = HttpServerParams {
        runtime: system.runtime()?,
        logger,
        log_buffer,
        setup_complete: SetupCompleteFlag::new(true),
        ready: ready_flag,
        force_https,
        shutdown_handle: shutdown_handle.clone(),
    };

    let server = http_server::bind(params)?;
    let ready_for_http = ready_flag_for_set.clone();
    system.lifecycle.track(
        "http_server",
        actix::spawn(async move {
            if let Err(e) = server.await {
                ready_for_http.store(false, Ordering::SeqCst);
                log!(SystemError::HttpServerError(e));
            }
        }),
    );

    ready_flag_for_set.store(true, Ordering::SeqCst);
    if let Err(err) = sd_notify::notify(&[NotifyState::Ready]) {
        log!(SystemLog::SystemdNotifyFailed("Ready", err.to_string()));
    }
    log!(SystemLog::FullInitComplete);

    Ok(shutdown_rx)
}

pub fn start_external(system: &mut System, suricata_detection_tx: Sender<DetectionEvent>) {
    let (suricata_manager, app_config) = match system.runtime() {
        Ok(runtime) => (
            runtime.observability.suricata_manager.clone(),
            runtime.foundation.app_config.clone(),
        ),
        Err(err) => {
            log!(SystemError::UnexpectedError(err));
            return;
        }
    };
    if let Some(notify_interval) = sd_notify::watchdog_enabled()
        .map(|watchdog_timeout| watchdog_timeout / 2)
        .filter(|notify_interval| !notify_interval.is_zero())
    {
        system.lifecycle.spawn("systemd_watchdog", async move {
            let mut tick = interval(notify_interval);
            loop {
                tick.tick().await;
                if let Err(err) = sd_notify::notify(&[NotifyState::Watchdog]) {
                    log!(SystemLog::SystemdNotifyFailed("Watchdog", err.to_string()));
                }
            }
        });
    }

    let (suricata_shutdown, suricata_handle) = suricata_manager.run();
    system
        .lifecycle
        .graceful("suricata_manager", suricata_shutdown, suricata_handle);
    if let Some(handle) = SuricataMonitor::new(app_config, suricata_detection_tx).start() {
        system.lifecycle.track("suricata_monitor", handle);
    }
}

fn attach_ebpf(runtime: &mut SystemRuntime) -> Result<(), Error> {
    startup::data_plane::set_memory_limit()?;
    let cfg = runtime.foundation.app_config.load();
    let ingress_ifname = cfg.ebpf.ingress_ifname.clone();
    let egress_ifname = cfg.ebpf.egress_ifname.clone();
    drop(cfg);

    let (ingress, egress) = match (
        runtime.data_plane.ingress_ebpf.as_mut(),
        runtime.data_plane.egress_ebpf.as_mut(),
    ) {
        (Some(i), Some(e)) => (i, e),
        _ => return Ok(()),
    };

    let ingress_result = startup::data_plane::attach_xdp(ingress, &ingress_ifname, true);
    let egress_result = startup::data_plane::attach_xdp(egress, &egress_ifname, false);

    match (ingress_result, egress_result) {
        (Ok(ingress_mode), Ok(egress_mode)) => {
            let mut next_state = (**runtime.foundation.runtime_state.load()).clone();
            next_state.xdp.ingress_mode = ingress_mode;
            next_state.xdp.egress_mode = egress_mode;
            runtime.foundation.runtime_state.store(Arc::new(next_state));
        }
        _ => {
            log!(SystemLog::EbpfBringupFailed);
            runtime.foundation.ebpf_health.store(Arc::new(EbpfHealth::Unavailable));
        }
    }

    Ok(())
}
