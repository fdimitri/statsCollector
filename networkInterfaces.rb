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

  def parseFile_vendorInfo(device, opts)
    # Get PCI device Vendor + DeviceID if it exists
    if (File.exists?("#{device}/device/subsystem"))
      type = File.basename(File.readlink("#{device}/device/subsystem"))
    else
      type = "virt"
    end

    devInfo = {:bus => type}

    if (type == "pci")
      pciVendor = File.read("#{device}/device/vendor").strip
      pciDevice = File.read("#{device}/device/device").strip
      dsInfo = getPCIInfo(pciVendor, pciDevice)
    elsif (type == "usb")
      # Get USB device Vendor + DeviceID is NYI
      dsInfo = {:vendor => "USB", :device => "USB"}
    elsif (type == "virt")
      dsInfo = {:vendor => "VIRT", :device => "VIRT"}
    elsif (type == "virtio")
      dsInfo = {:vendor => "VirtIO", :device => "VirtIO-NET"}
      # We should check #{device}/device/driver/module/drivers/ for virtio
    end
    return({:action => :mergeSimple, :data => dsInfo})
  end

  def readLink_Generic(device, opts)
    if (opts.has_key?(:default))
      default = opts[:default]
    else
      default = 'Unknown'
    end
    if (File.exists?(device + opts[:location]))
      k = File.basename(File.readlink(device + opts[:location]))
    else
      k = default
    end
    return(k)
  end

  def dirExists_Generic(device, opts)
    if (File.exists?(device + opts[:location]))
      return(true)
    end
    return(false)
  end

  def parseDir_xferStats(device, opts)
    if (!(File.exists?(device + opts[:location])))
      return(false)
    end

    # Initialize counters hash
    # This is kind of a nasty way to define the hash, the lower functions
    #  should actually create the lower level hashes as needed. On the other
    #  hand, it does give us atleast an empty hash if there are no counters..
    counters = {'RX' => { 'errors' => { }}, 'TX' => { 'errors' => { }}}

    # Read all the statistics files and return them, do some trimming
    Dir.glob(device + opts[:location] + '*') do |statsc|
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
    return(counters)
  end

  def readLink_moduleName(device, opts)
    # Check to see if there's a kernel module associated with this interface
    moduleLink = "#{device}/device/driver/module"
    moduleName = "none"
    if (File.exists?(moduleLink))
      moduleName = File.basename(File.readlink(moduleLink))
    end
    return(moduleName)
  end

  def parseFile_MTU(device, opts)
    if (!File.exists?(device + opts[:location]))
      return(false)
    end
    return(File.read(device + opts[:location]).to_i)
  end

  def parseFile_OperState(device, opts)
    if (!File.exists?(device + opts[:location]))
      return(false)
    end
    return(File.read(device + opts[:location]))
  end

  def parseFile_LinkSpeed(device, opts)
    if (!File.exists?(device + opts[:location]))
      return(false)
    end
    begin
      res = File.read(device + opts[:location])
    rescue
      res = 'NA'
    end
    return(res)
  end


  def parseFile_netType(device, opts)
    # Get the device flags and check them against our device flag list
    # Device list is a partial of "include/uapi/linux/if_arp.h"
    netType = @netTypes.key(File.read(device + opts[:location]).to_i)
    flags = Integer(File.read(device + "/flags"))
    flagList = []
    @netDeviceFlags.each do |desc, flag|
      if ((flags & flag) == flag)
        flagList << desc
      end
    end
    flagString = flagList.join(" ")
    rData = {:flagString => flagString, :flagValue => flags, :netType => netType}
    return({:action => :mergeEach, :data => rData})
  end

  def checkFlagsSimple(device, opts, interface)
    opts[:flags].each do |f|
      f.each do |k,v|
        if (k == :forceTrueWithOr && (interface[:flagValue] & v == v))
          return(true)
        end
      end
    end
    return(false)
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
        :vendorInfo => {
          :action => 'parseFile',
          :location => '/device/vendor',
          :default => false,
        },
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
        :netType => {
          :action => 'parseFile',
          :location => '/type',
          :default => false,
        },
        :subSystem => {
          :action => 'readLink',
          :location => '/device/subsystem',
          :default => 'Dvirtual',
        },
        :isLoopback => {
          :action => 'checkFlagsSimple',
          :flags => [
            {:forceTrueWithOr => @netDeviceFlags["LOOPBACK"]},
          ],
          :default => false,
        },
        :isBridgeDevice => {
          :action => 'dirExists',
          :location => '/bridge',
          :default => 'false',
        },
        :MTU => {
          :action => 'parseFile',
          :location => '/mtu',
          :default => false,
        },
        :OperState => {
          :action => 'parseFile',
          :location => '/operstate',
          :default => 'unknown',
        },
        :LinkSpeed => {
          :action => 'parseFile',
          :location => '/speed',
          :default => 0,
        },
        :bridgeParent => {
          :action => 'readLink',
          :location => '/brport/bridge',
          :default => false,
        },
        :xferStats => {
          :action => 'parseDirectory',
          :location => '/statistics/',
        },
      }

      parseList.each do |k, v|
        case (v[:action])
        when 'readLink'
          #puts "Checking File.exists? #{device}#{v[:location]}"
          callFunction = 'readLink_' + k.to_s
          if (self.respond_to?(callFunction))
            thisInterface[k] = self.send(callFunction, device, v);
          else
            thisInterface[k] = readLink_Generic(device, v)
          end
        when 'parseFile'
          if (!File.exists?(device + v[:location]))
            break
          end
          callFunction = 'parseFile_' + k.to_s
          if (self.respond_to?(callFunction))
            res = self.send(callFunction, device, v)
            if (res.is_a?(Hash))
              if (res[:action] == :mergeEach)
                res[:data].each do |k,v|
                  thisInterface[k] = v
                end
              elsif (res[:action] == :mergeSimple)
                thisInterface[k] = res[:data]
              end
            else
              thisInterface[k] = res
            end
          else
            #raise.MyException.new("Unhandled fileParse #{v[:action]}")
            puts "NYI #{callFunction}"
          end
        when 'parseDirectory'
          callFunction = 'parseDir_' + k.to_s
          if (self.respond_to?(callFunction))
            thisInterface[k] = self.send(callFunction, device, v);
          else
            #raise.MyException.new("Unhandled dirParse #{v[:action]}")
            puts "NYI #{callFunction}"
          end
        when 'checkFlagsSimple'
          res = checkFlagsSimple(device, v, thisInterface)
          thisInterface[k] = res
        when 'readLink'
          callFunction = 'readLink_' + k.to_s
          if (self.respond_to?(callFunction))
            thisInterface[k] = self.send(callFunction, device, v)
          else
            puts "NYI #{callFunction}"
          end
        when 'dirExists'
          thisInterface[k] = dirExists_Generic(device, v)
        else
          puts "Unhandled Directive: #{v[:action]}"
          raise.MyException.new("Unhandled directive #{v[:action]}")
        end
      end
      interfaceList << {deviceName => thisInterface}
    end
    return(interfaceList)
  end
end

# Define the options we'll pass to LinuxSysNet.new()
lsnOpts = { }

# Possible locations for pci.ids
pciIDLocations = [ "/usr/share/hwdata/pci.ids", "/usr/share/misc/pci.ids" ]

# Check to see if any of those work
pciIDLocations.each do |val|
  if (File.exists?(val))
    lsnOpts[:pciLocation] = val
    break
  end
end
if (!lsnOpts.has_key?(:pciLocation))
  puts "Couldn't find PCI-ID descriptor"
  exit 0
end
nc = LinuxSysNet.new(lsnOpts)
ap nc.getInterfaces()
