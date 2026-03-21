packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = ">= 1.1.0"
    }
    virtualbox = {
      source  = "github.com/hashicorp/virtualbox"
      version = ">= 1.0.0"
    }
  }
}

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------
variable "ubuntu_iso_url" {
  type    = string
  default = "https://releases.ubuntu.com/24.04/ubuntu-24.04-live-server-amd64.iso"
}

variable "ubuntu_iso_checksum" {
  type    = string
  default = "sha256:none"
  description = "SHA-256 checksum of the Ubuntu 24.04 Server ISO. Update before building."
}

variable "netguardia_binary" {
  type    = string
  default = "../target/release/net-guardia"
  description = "Path to the pre-built NetGuardia binary."
}

variable "ssh_username" {
  type    = string
  default = "netguardia"
}

variable "ssh_password" {
  type      = string
  default   = "netguardia"
  sensitive = true
}

variable "disk_size" {
  type    = string
  default = "20480"
  description = "Virtual disk size in MB."
}

variable "memory" {
  type    = string
  default = "2048"
}

variable "cpus" {
  type    = string
  default = "2"
}

# ---------------------------------------------------------------------------
# Source: QEMU (produces QCOW2)
# ---------------------------------------------------------------------------
source "qemu" "netguardia" {
  iso_url          = var.ubuntu_iso_url
  iso_checksum     = var.ubuntu_iso_checksum
  output_directory = "output-qcow2"
  format           = "qcow2"
  disk_size        = var.disk_size
  memory           = var.memory
  cpus             = var.cpus
  headless         = true

  ssh_username     = var.ssh_username
  ssh_password     = var.ssh_password
  ssh_timeout      = "30m"

  shutdown_command  = "echo '${var.ssh_password}' | sudo -S shutdown -P now"
  boot_wait         = "5s"

  http_directory = "cloud-init"
  boot_command = [
    "c<wait>",
    "linux /casper/vmlinuz autoinstall ds='nocloud-net;s=http://{{ .HTTPIP }}:{{ .HTTPPort }}/' ",
    "--- <enter><wait>",
    "initrd /casper/initrd<enter><wait>",
    "boot<enter>"
  ]

  vm_name          = "netguardia"
  net_device       = "virtio-net"
  disk_interface   = "virtio"
  accelerator      = "kvm"
}

# ---------------------------------------------------------------------------
# Source: VirtualBox (produces OVA)
# ---------------------------------------------------------------------------
source "virtualbox-iso" "netguardia" {
  iso_url          = var.ubuntu_iso_url
  iso_checksum     = var.ubuntu_iso_checksum
  output_directory = "output-ova"
  format           = "ova"
  disk_size        = var.disk_size
  memory           = var.memory
  cpus             = var.cpus
  headless         = true
  guest_os_type    = "Ubuntu_64"

  ssh_username     = var.ssh_username
  ssh_password     = var.ssh_password
  ssh_timeout      = "30m"

  shutdown_command  = "echo '${var.ssh_password}' | sudo -S shutdown -P now"
  boot_wait         = "5s"

  http_directory = "cloud-init"
  boot_command = [
    "c<wait>",
    "linux /casper/vmlinuz autoinstall ds='nocloud-net;s=http://{{ .HTTPIP }}:{{ .HTTPPort }}/' ",
    "--- <enter><wait>",
    "initrd /casper/initrd<enter><wait>",
    "boot<enter>"
  ]

  vboxmanage = [
    ["modifyvm", "{{ .Name }}", "--nic2", "intnet"],
    ["modifyvm", "{{ .Name }}", "--intnet2", "netguardia-internal"]
  ]
}

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
build {
  sources = [
    "source.qemu.netguardia",
    "source.virtualbox-iso.netguardia"
  ]

  # ------ Upload artifacts ------

  provisioner "file" {
    source      = var.netguardia_binary
    destination = "/tmp/net-guardia"
  }

  provisioner "file" {
    source      = "../deploy/netguardia.service"
    destination = "/tmp/netguardia.service"
  }

  provisioner "file" {
    source      = "../deploy/setup-wizard.sh"
    destination = "/tmp/setup-wizard.sh"
  }

  provisioner "file" {
    source      = "../deploy/logrotate.conf"
    destination = "/tmp/netguardia-logrotate.conf"
  }

  # ------ Install everything ------

  provisioner "shell" {
    inline = [
      "set -ex",

      "# Create directories",
      "sudo mkdir -p /opt/netguardia/bin",
      "sudo mkdir -p /var/log/netguardia",

      "# Install binary",
      "sudo install -m 0755 /tmp/net-guardia /opt/netguardia/bin/net-guardia",

      "# Install systemd unit",
      "sudo install -m 0644 /tmp/netguardia.service /etc/systemd/system/netguardia.service",
      "sudo systemctl daemon-reload",
      "sudo systemctl enable netguardia.service",

      "# Install setup wizard",
      "sudo install -m 0755 /tmp/setup-wizard.sh /opt/netguardia/bin/setup-wizard.sh",

      "# Install logrotate config",
      "sudo install -m 0644 /tmp/netguardia-logrotate.conf /etc/logrotate.d/netguardia",

      "# Cleanup temp files",
      "rm -f /tmp/net-guardia /tmp/netguardia.service /tmp/setup-wizard.sh /tmp/netguardia-logrotate.conf",

      "# Configure first-boot setup wizard via rc.local",
      "sudo tee /etc/rc.local > /dev/null << 'RCEOF'",
      "#!/bin/bash",
      "if [ ! -f /opt/netguardia/config.toml ]; then",
      "  /opt/netguardia/bin/setup-wizard.sh",
      "fi",
      "exit 0",
      "RCEOF",
      "sudo chmod +x /etc/rc.local"
    ]
  }

  # ------ Final cleanup ------

  provisioner "shell" {
    inline = [
      "sudo apt-get -y autoremove",
      "sudo apt-get -y clean",
      "sudo rm -rf /tmp/* /var/tmp/*",
      "sudo truncate -s 0 /var/log/syslog",
      "history -c"
    ]
  }
}
