require 'yaml'
require 'awesome_print'

class MyException < StandardError
  attr_accessor :object

  def initialize(message = nil, object = nil)
    super(message)
    self.object = objectend
  end
end

class LinuxSysNet
  attr_accessor :netDeviceFlags, :netTypes, :pciDB, :opts

  def initialize(opts)
    @netDeviceFlags = {
      "UP" => 0x1,
      "BROADCAST" => 0x2,
      "DEBUG" => 0x4,
      "LOOPBACK" => 0x8,
      "POINTTOPOINT" => 0x10,
      "NOTRAILERS" => 0x20,
      "RUNNING" => 0x40,
      "NOARP" => 0x80,
      "PROMISC" => 0x100,
      "ALLMULTI" => 0x200,
      "MASTER" => 0x400,
      "SLAVE" => 0x800,
      "MULTICAST" => 0x1000,
      "PORTSEL" => 0x2000,
      "AUTOMEDIA" => 0x4000,
      "DYNAMIC" => 0x8000,
      "L1_UP" => 0x10000,
      "DORMANT" => 0x20000,
      "ECHO" => 0x40000
    }

    @netTypes = {
      "Ethernet" => 1,
      "FireWire IPv4" => 24,
      "InfiniBand" => 32,
      "SLIP" => 256,
      "CAN" => 280,
      "PPP" => 512,
      "Cisco/HDLC" => 513,
      "IPv4 in IPv4" => 768,
      "IPv6 in IPv6" => 769,
      "Loopback" => 772,
      "Sit/IPv6-in-IPv4" => 776,
      "IP over DDP Tunnel" => 777,
      "IP GRE" => 778,
      "HiPo Parallel" => 780,
      "IrDA" => 783,
      "FC P2P" => 784,
      "FC Arb Loop" => 785,
      "FC Pub Loop" => 786,
      "FC Fabric" => 787,
      "802.11" => 801,
      "GRE over IPv6" => 823,
      "NetLink" => 824,
      "6LoWPAN" => 825,
      "VOID" => 0xFFFF,
      "None" => 0xFFFE
    }

    @pciDB = {}

    @opts = {
      :pciLocation => false,
    }
    opts.each do |k,v|
      if (@opts.has_key?(k))
        @opts[k] = v
      end
    end
    loadPCIFile(@opts[:pciLocation])
  end

  def loadPCIFile(fileName)
    reVend = Regexp.new("^(?<vendor_id>[[:xdigit:]]{4})\s+(?<vendor_string>[^#\n\r]+).*$")
    reDev  = Regexp.new("^\t(?<device_id>[[:xdigit:]]{4})\s+(?<device_string>[^#\n\r]+).*$")
    reComment = Regexp.new("^\#.*$")
    currentVendor = String.new()
    File.readlines(fileName).each do |line|
      if (reComment =~ line)
        next
      end
      if (res = (reVend.match(line)))
        vendorID = "0x" + res[:vendor_id].to_s
        vendorID = "%s" % vendorID.to_s
        currentVendor = vendorID
        @pciDB[vendorID] = {
          :name => res[:vendor_string],
          :devices => { }
        }
        next
      elsif (res = (reDev.match(line)))
        deviceID = "0x" + res[:device_id].to_s
        deviceID = "%s" % deviceID.to_s
        @pciDB[currentVendor][:devices][deviceID] = res[:device_string]
        next
      end
    end
  end

  def getPCIInfo(venID, devID, subsys = nil, subdev = nil)
    vendor = venID.to_s
    device = devID.to_s
    rVal = {
      :vendor => {
        :desc => false,
        :rawid => venID,
      },
      :device => {
        :desc => false,
        :rawid => devID,
      },
    }
    if (@pciDB.has_key?(vendor))
      rVal[:vendor] = @pciDB[vendor][:name]
      if (@pciDB[vendor][:devices].has_key?(device))
        rVal[:device] = @pciDB[vendor][:devices][device]
      end
    else
      # Log unidentified PCI device!
    end
    return(rVal)
  end

  def getInterfaces
    # Check https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-net for more info
    sysDir = "/sys/class/net"
    interfaceList = []
    Dir.glob(sysDir + "/*") do |device|
      deviceName = File.basename(device)
      # /carrier {0,1} 0 = phys down, 1 = phys up
      # /duplex {half,full} seriously.
      # /flags == string, hex, see @netDeviceFlags -- incorrect vs ifconfig though, we get 0x1303, ifconfig reports 4163 or 0x1043
      # /mtu {integer}
      # /operstate {unknown, notpresent, down, lowerlayerdown, testing, dormant, up}
      # /speed -- in mbits, only for Ethernetish devices
      # /type -- see @netTypes
      # /address -- MAC
      # /dormant -- {0,1} 0 = not Dormant, 1 = Dormant, ie needs 802.1x auth
      thisInterface = {}
      parseList = {
        :driverName => {
          :action => 'readLink',
          :location => '/device/driver',
          :default => false,
        },
        :moduleName => {
          :action => 'readLink',
          :location => '/device/driver/module',
          :default => false,
        },
        :bridgeParent => {
          :action => 'readLink',
          :location => '/brport/bridge',
          :default => false,
        },
        :netType => {
          :action => 'parseFile',
          :location => '/type',
          :default => false,
        },
        :xferStats => {
          :action => 'parseDirectory',
          :location => '/statistics/',
        },
        :subSystem => {
          :action => 'readLink',
          :location => '/device/subsystem',
          :default => 'virtual',
        },
        :isLoopback => {
          :action => 'checkFlagsSimple',
          :flags => {
            :forceTrueWithOr => @netDeviceFlags["LOOPBACK"]
          },
          :default => false,
        },
        :isBridgeDevice => {
          :action => 'parseDirectory',
          :location => '/bridge/',
        }
      }

      parseList.each do |k, v|
        case (v[:action])
        when 'readLink'
	puts "Checking File.exists? #{device} #{v[:location]}"
          if (File.exists?(device + v[:location]))
            thisInterface[k] = File.basename(File.readlink(device + v[:location]))
          else
            thisInterface[k] = v[:default]
          end

        when 'parseFile'
          if (self.respond_to?('parseFile_#{k}'))
            thisInterface[k] = self.send("parseFile_#{k}", v);
          else
            #raise.MyException.new("Unhandled fileParse #{v[:action]}")
            puts "NYI"
          end
        when 'parseDirectory'
          if (self.respond_to?('parseDir_#{k}'))
            thisInterface[k] = self.send("parseDir_#{k}", v);
          else
            #raise.MyException.new("Unhandled fileParse #{v[:action]}")
            puts "NYI"
          end
        when 'checkFlagsSimple'
          puts "NYI"
        else
          puts "Unhandled Directive: #{v[:action]}"
          raise.MyException.new("Unhandled directive #{v[:action]}")
        end
      end
	puts "New Collection Data:"
	ap thisInterface
      # Check to see if there's a kernel module associated with this interface
      moduleLink = "#{device}/device/driver/module"
      moduleName = "none"
      if (File.exists?(moduleLink))
        moduleName = File.basename(File.readlink(moduleLink))
      end

      # Check to see if the device is in a bridge
      bridgeLink = "#{device}/brport/bridge"
      if (File.exists?(bridgeLink))
        bridgeDevice = File.basename(File.readlink(bridgeLink))
      else
        bridgeDevice = false
      end

      # Get the device flags and check them against our device flag list
      # Device list is a partial of "include/uapi/linux/if_arp.h"
      netType = @netTypes.key(File.read("#{device}/type").to_i)
      flags = Integer(File.read("#{device}/flags"))
      flagList = []
      @netDeviceFlags.each do |desc, flag|
        if ((flags & flag) == flag)
          flagList << desc
        end
      end
      flagString = flagList.join(" ")

      # This is kind of a nasty way to define the hash, the lower functions
      #  should actually create the lower level hashes as needed. On the other
      #  hand, it does give us atleast an empty hash if there are no counters..
      counters = {'RX' => { 'errors' => { }}, 'TX' => { 'errors' => { }}}

      # Read all the statistics files and return them, do some trimming
      Dir.glob("#{device}/statistics/*") do |statsc|
        newID = File.basename(statsc).gsub("_"," ")
        inData = File.read(statsc).strip.to_i
        priCategory = false
        if (newID.match(/errors|dropped/))
          #newID.gsub!("errors", "")
          subCategory = 'errors'
        end

        if (newID.match(/rx\s/))
          newID.gsub!("rx ","").capitalize!
          priCategory = 'RX'
        elsif (newID.match(/tx/))
          newID.gsub!("tx ","").capitalize!
          priCategory = 'TX'
        else
          counters[newID.capitalize!] = inData
        end
        if (priCategory)
          if (subCategory)
            counters[priCategory][subCategory][newID] = inData
          else
            counters[priCategory][newID] = inData
          end
        end
      end

      # Get PCI device Vendor + DeviceID if it exists
      if (File.exists?("#{device}/device/subsystem"))
        type = File.basename(File.readlink("#{device}/device/subsystem"))
      else
        type = "virt"
      end
      # Get USB device Vendor + DeviceID..
      # NYI

      devInfo = {:bus => type}

      if (type == "pci")
        pciVendor = File.read("#{device}/device/vendor").strip
        pciDevice = File.read("#{device}/device/device").strip
        dsInfo = getPCIInfo(pciVendor, pciDevice)
      elsif (type == "usb")
        dsInfo = {:vendor => "USB", :device => "USB"}
      elsif (type == "virt")
        dsInfo = {:vendor => "VIRT", :device => "VIRT"}
      elsif (type == "virtio")
        dsInfo = {:vendor => "VirtIO", :device => "VirtIO-NET"}
        # We should check #{device}/device/driver/module/drivers/ for virtio
      end


      devInfo.merge!(dsInfo)

      # Create hash and add to array
      interfaceList << {
        :deviceName => deviceName,
        :moduleName => moduleName,
        :devInfo => devInfo,
        :netType => netType,
        :flagString => flagString,
        :bridgeDevice => bridgeDevice,
        :counters => counters,
      }
    end
    interfaceList
  end

end


lsnOpts = {
  :pciLocation => "/usr/share/misc/pci.ids"
}
nc = LinuxSysNet.new(lsnOpts)
ap nc.getInterfaces()
