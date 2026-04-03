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
  type        = string
  description = "SHA-256 checksum of the Ubuntu 24.04 Server ISO (e.g. sha256:abcdef...). Must be provided explicitly."

  validation {
    condition     = can(regex("^sha256:[0-9a-fA-F]{64}$", var.ubuntu_iso_checksum))
    error_message = "ubuntu_iso_checksum must be a valid SHA-256 checksum in the form 'sha256:<64 hex chars>'. Do not use 'sha256:none'."
  }
}

variable "netguardia_binary" {
  type        = string
  default     = "../target/release/net-guardia"
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
  type        = string
  default     = "20480"
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

variable "accelerator" {
  type        = string
  default     = "kvm"
  description = "QEMU accelerator: 'kvm' (default) or 'none' for environments without KVM support."

  validation {
    condition     = contains(["kvm", "none"], var.accelerator)
    error_message = "accelerator must be 'kvm' or 'none'."
  }
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
  accelerator      = var.accelerator
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

  # ------ KVM fallback warning ------

  provisioner "shell" {
    inline = [
      "if [ '${var.accelerator}' = 'none' ]; then",
      "  echo '⚠  WARNING: Building without KVM acceleration. This will be significantly slower.'",
      "  echo '⚠  Set accelerator=kvm for production builds.'",
      "fi"
    ]
  }

  # ------ Upload artifacts ------

  provisioner "file" {
    source      = var.netguardia_binary
    destination = "/tmp/net-guardia"
  }

  provisioner "file" {
    source      = "../deploy/scripts/install.sh"
    destination = "/tmp/install.sh"
  }

  provisioner "file" {
    source      = "../deploy/netguardia.service"
    destination = "/tmp/netguardia.service"
  }

  provisioner "file" {
    source      = "../deploy/logrotate.conf"
    destination = "/tmp/logrotate.conf"
  }

  provisioner "file" {
    source      = "../deploy/setup-wizard.sh"
    destination = "/tmp/setup-wizard.sh"
  }

  # ------ Debug binary gate ------

  provisioner "shell" {
    inline = [
      "set -e",
      "echo 'Checking binary is not a debug build...'",
      "if file /tmp/net-guardia | grep -q 'not stripped'; then",
      "  echo 'FATAL: Binary is a debug build (not stripped). Use a release build for VM images.'",
      "  exit 1",
      "fi",
      "echo 'Binary check passed: stripped release build.'"
    ]
  }

  # ------ Install runtime dependencies (SQLCipher needs OpenSSL) ------

  provisioner "shell" {
    inline = [
      "set -e",
      "if command -v apt-get &>/dev/null; then",
      "  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y libssl3",
      "elif command -v dnf &>/dev/null; then",
      "  sudo dnf install -y openssl-libs",
      "fi"
    ]
  }

  # ------ Install via install.sh --local ------

  provisioner "shell" {
    inline = [
      "set -e",
      "chmod +x /tmp/install.sh",

      "# Lay out deploy dir structure so install.sh can find service/logrotate files",
      "sudo mkdir -p /tmp/deploy/scripts",
      "cp /tmp/install.sh /tmp/deploy/scripts/install.sh",
      "cp /tmp/netguardia.service /tmp/deploy/netguardia.service",
      "cp /tmp/logrotate.conf /tmp/deploy/logrotate.conf",

      "sudo /tmp/deploy/scripts/install.sh --local /tmp/net-guardia",

      "# Install setup wizard",
      "sudo install -m 0755 /tmp/setup-wizard.sh /opt/netguardia/bin/setup-wizard.sh",

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
