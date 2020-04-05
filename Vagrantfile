# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|

  config.vm.box = "bento/ubuntu-14.04"
  config.vm.box_check_update = true
  config.vm.boot_timeout = 600

  # Main development box with build essentials, FOSS DBs
  config.vm.define "unum", primary: true do |definition|
    definition.vm.hostname = "vmbuild"
    definition.vm.network "private_network", type: "dhcp"
    definition.vm.provider :virtualbox do |vb|
      vb.customize ["modifyvm", :id, "--memory", "1024"]
    end
    scripts = [
      "bootstrap.sh",
      "devel.sh",
      "mysql.sh",
      "apache.sh",
      "node.sh",
      "build.sh",
    ]
    scripts.each { |script|
      definition.vm.provision :shell, privileged: false, :path => "scripts/vagrant/" << script
    }
  end

  # Sync time
  # https://stackoverflow.com/questions/19490652/how-to-sync-time-on-host-wake-up-within-virtualbox
  config.vm.provider 'virtualbox' do |vb|
    vb.customize [ "guestproperty", "set", :id, "/VirtualBox/GuestAdd/VBoxService/--timesync-set-threshold", 1000 ]
  end

end
