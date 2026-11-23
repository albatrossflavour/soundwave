# frozen_string_literal: true

require 'spec_helper'

describe 'soundwave' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      let(:dir) { '/opt/puppetlabs/soundwave' }
      let(:pre_condition) { 'function node_encrypt::secret($data) { $data }' }
      let(:required) { { 'pe_token' => sensitive('TOKEN'), 'gmp_password' => sensitive('pa%ss'), 'pe_host' => 'pe.example.com' } }
      let(:params) { required }
      let(:unit) { catalogue.resource('systemd::timer', 'soundwave.timer')[:service_content] }
      let(:config_ini) { catalogue.resource('file', "#{dir}/python/config.ini")[:content] }
      let(:el8) { os_facts[:os]['family'] == 'RedHat' && os_facts[:os]['release']['major'] == '8' }

      context 'with the required parameters' do
        it { is_expected.to compile.with_all_deps }

        it 'installs Python from the OS repos, never EPEL' do
          is_expected.to contain_class('python').with(ensure: 'present', venv: 'present', use_epel: false, version: el8 ? 'python39' : '3')
        end

        it { is_expected.to contain_file(dir).with_ensure('directory') }
        it { is_expected.to contain_file("#{dir}/python").with_ensure('directory') }
        it { is_expected.to contain_file("#{dir}/python/src").with(recurse: true, purge: true, ignore: ['__pycache__'], source: 'puppet:///modules/soundwave/python/src') }
        it { is_expected.to contain_file("#{dir}/python/requirements.txt").that_requires("File[#{dir}/python/src]") }

        ['/var/lib/soundwave', '/var/lib/soundwave/cassettes'].each do |d|
          it { is_expected.to contain_file(d).with(ensure: 'directory', owner: 'root', group: 'root', mode: '0770') }
        end

        it { is_expected.to contain_python__pyvenv('soundwave-env').with(venv_dir: "#{dir}/python/env", systempkgs: true) }
        it { is_expected.to contain_python__requirements("#{dir}/python/requirements.txt").with_virtualenv("#{dir}/python/env") }

        it 'runs nightly, and survives a reboot' do
          is_expected.to contain_systemd__timer('soundwave.timer').with(active: true, enable: true)
            .with_timer_content(%r{^OnCalendar=daily$}).with_timer_content(%r{^WantedBy=timers\.target$})
        end

        it 'runs the openvas cassette, allowed to fail, then pushes' do
          expect(unit).to include("ExecStart=-#{dir}/python/env/bin/python3 #{dir}/python/src/cassettes/openvas.py\n")
          expect(unit).not_to include('vuls.py')
          expect(unit).not_to include('nessus.py')
          expect(unit).not_to include('rapid7.py')
          expect(unit).to end_with("ExecStart=#{dir}/python/env/bin/python3 #{dir}/python/src/soundwave.py\n")
        end

        it 'keeps the PE token and host in a root-only config' do
          is_expected.to contain_file("#{dir}/python/config.ini").with(owner: 'root', group: 'root', mode: '0600')
          expect(config_ini).to include("host = pe.example.com\n")
          expect(config_ini).to include("token = TOKEN\n")
          expect(config_ini).not_to include('token_file')
        end

        it 'leaves the optional settings empty, which the Python reads as unset' do
          ['metrics_file', 'correlation_exceptions', 'findings_api_host', 'post_body_filepath', 'scan_name'].each do |key|
            expect(config_ini).to match(%r{^#{key} = $})
          end
        end

        context 'with every optional setting given' do
          let(:params) do
            required.merge('metrics_file' => '/var/lib/textfile/soundwave.prom', 'correlation_exceptions' => 'greenbone:1.2.3',
                           'findings_api_host' => 'pe.example.com', 'post_body_filepath' => '/tmp/body.json',
                           'scan_name' => 'Weekly', 'host_map_file' => '/opt/hosts.json')
          end

          it 'writes each one' do
            expect(config_ini).to include("metrics_file = /var/lib/textfile/soundwave.prom\n", "correlation_exceptions = greenbone:1.2.3\n",
                                          "findings_api_host = pe.example.com\n", "post_body_filepath = /tmp/body.json\n",
                                          "scan_name = Weekly\n", "host_map_file = /opt/hosts.json\n")
          end
        end

        it "maps addresses to certnames with the openvas module's own host map" do
          expect(config_ini).to include("host_map_file = /opt/greenbone-community-container/scan-hosts.json\n")
        end

        it 'reads Greenbone as admin when no observer is configured' do
          is_expected.to contain_file("#{dir}/python/gvm-tools.conf").with_content(%r{^username = admin$})
        end

        it 'escapes % in the GMP password, as gvm-tools interpolates it' do
          is_expected.to contain_file("#{dir}/python/gvm-tools.conf").with(owner: 'root', group: 'root', mode: '0600')
            .with_content(%r{^password = pa%%ss$})
        end

      end

      context 'with the vuls cassette and without the openvas one' do
        let(:params) { required.merge('vuls_cassette' => true, 'openvas_cassette' => false) }

        it 'runs only the vuls cassette, writing into the cassette directory' do
          expect(unit).not_to include('openvas.py')
          expect(unit).to include("cassettes/vuls.py --results-dir=/var/lib/vuls/results --complete-file=/var/lib/vuls/last-complete-run")
          expect(unit).to include("--out=/var/lib/soundwave/cassettes/vuls.json\n")
        end
      end

      context 'with the nessus cassette reading files' do
        let(:params) { required.merge('nessus_cassette' => true) }

        it 'runs it after openvas and before the push' do
          expect(unit).to include("cassettes/openvas.py\nExecStart=-#{dir}/python/env/bin/python3 #{dir}/python/src/cassettes/nessus.py\nExecStart=#{dir}")
        end

        it 'creates the export directory for files to be dropped in' do
          is_expected.to contain_file('/var/lib/soundwave/exports').with(ensure: 'directory', mode: '0770')
          is_expected.to contain_file('/var/lib/soundwave/exports/nessus').with(ensure: 'directory', mode: '0770')
        end

        it 'writes no API settings' do
          expect(config_ini).to match(%r{^\[NESSUS\]\nurl = \n})
          expect(config_ini).to include("export_dir = /var/lib/soundwave/exports/nessus\n")
        end
      end

      context 'with the nessus cassette exporting over the API' do
        let(:params) do
          required.merge('nessus_cassette' => true, 'nessus_url' => 'https://nessus.example.com:8834',
                         'nessus_access_key' => sensitive('AK'), 'nessus_secret_key' => sensitive('S%K'),
                         'nessus_scans' => ['Weekly Linux', 'Weekly Windows'])
        end

        it 'writes the keys and scans, doubling any % for ConfigParser' do
          expect(config_ini).to include("url = https://nessus.example.com:8834\n", "access_key = AK\n",
                                        "secret_key = S%%K\n", "scans = Weekly Linux|Weekly Windows\n")
        end

        it 'creates no export directory' do
          is_expected.not_to contain_file('/var/lib/soundwave/exports/nessus')
        end
      end

      context 'with the nessus API and no keys' do
        let(:params) { required.merge('nessus_cassette' => true, 'nessus_url' => 'https://nessus.example.com:8834') }

        it { is_expected.to compile.and_raise_error(%r{set nessus_access_key, nessus_secret_key and nessus_scans}) }
      end

      context 'with the rapid7 cassette generating a report' do
        let(:params) do
          required.merge('rapid7_cassette' => true, 'rapid7_url' => 'https://insightvm.example.com:3780',
                         'rapid7_username' => 'soundwave', 'rapid7_password' => sensitive('pw'),
                         'rapid7_report' => 'Soundwave XML')
        end

        it 'runs it before the push' do
          expect(unit).to include("ExecStart=-#{dir}/python/env/bin/python3 #{dir}/python/src/cassettes/rapid7.py\n")
        end

        it 'writes the console settings' do
          expect(config_ini).to include("url = https://insightvm.example.com:3780\n", "username = soundwave\n",
                                        "password = pw\n", "report = Soundwave XML\n")
        end
      end

      context 'with the rapid7 API and no report' do
        let(:params) do
          required.merge('rapid7_cassette' => true, 'rapid7_url' => 'https://insightvm.example.com:3780',
                         'rapid7_username' => 'soundwave', 'rapid7_password' => sensitive('pw'))
        end

        it { is_expected.to compile.and_raise_error(%r{set rapid7_username, rapid7_password and rapid7_report}) }
      end

      context 'with the rapid7 cassette reading files from a directory of its own' do
        let(:params) { required.merge('rapid7_cassette' => true, 'rapid7_export_dir' => '/srv/rapid7') }

        it 'manages that directory and not its parent' do
          is_expected.to contain_file('/srv/rapid7').with(ensure: 'directory', mode: '0770')
          is_expected.not_to contain_file('/srv')
          is_expected.not_to contain_file('/var/lib/soundwave/exports')
        end
      end

      context 'with both file-mode cassettes sharing one drop folder' do
        let(:params) do
          required.merge('nessus_cassette' => true, 'nessus_export_dir' => '/srv/scans',
                         'rapid7_cassette' => true, 'rapid7_export_dir' => '/srv/scans')
        end

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_file('/srv/scans').with(ensure: 'directory') }
      end

      context 'with an export directory Soundwave already manages' do
        let(:params) { required.merge('nessus_cassette' => true, 'nessus_export_dir' => '/var/lib/soundwave/cassettes') }

        it { is_expected.to compile.with_all_deps }
      end

      context 'with threat intel off, the default' do
        it { is_expected.not_to contain_file('/var/lib/soundwave/threat-intel') }
        it { expect(config_ini).to include("threat_intel = off\n") }
        it { expect(config_ini).to include("threat_intel_in_vr = 0\n") }
      end

      context 'with threat intel downloaded' do
        let(:params) { required.merge('threat_intel' => 'download') }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.to contain_file('/var/lib/soundwave/threat-intel').with(ensure: 'directory', mode: '0770') }

        it 'tells the Python where to fetch from and keep the files' do
          expect(config_ini).to include("threat_intel = download\nthreat_intel_dir = /var/lib/soundwave/threat-intel\n")
          expect(config_ini).to include("kev_url = https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\n")
          expect(config_ini).to include("epss_url = https://epss.empiricalsecurity.com/epss_scores-current.csv.gz\n")
        end
      end

      context 'with threat intel read from a directory Soundwave already manages' do
        let(:params) { required.merge('threat_intel' => 'directory', 'threat_intel_dir' => '/var/lib/soundwave/cassettes') }

        it { is_expected.to compile.with_all_deps }
      end

      context 'with threat intel shown in the PE summary' do
        let(:params) { required.merge('threat_intel' => 'download', 'threat_intel_in_vr' => true) }

        it { expect(config_ini).to include("threat_intel_in_vr = 1\n") }
      end

      context 'with an internal mirror whose URL carries a %' do
        let(:params) { required.merge('threat_intel' => 'download', 'kev_url' => 'https://mirror.example.com/kev%20feed.json') }

        it { expect(config_ini).to include("kev_url = https://mirror.example.com/kev%%20feed.json\n") }
      end

      context 'with % in an export path and the nessus url' do
        let(:params) do
          required.merge('nessus_cassette' => true, 'nessus_url' => 'https://nessus.example.com/%7Esvc',
                         'nessus_access_key' => sensitive('ak'), 'nessus_secret_key' => sensitive('sk'),
                         'nessus_scans' => ['Weekly'], 'rapid7_cassette' => true, 'rapid7_export_dir' => '/srv/100%')
        end

        it 'doubles it for ConfigParser' do
          expect(config_ini).to include("url = https://nessus.example.com/%%7Esvc\n")
          expect(config_ini).to include("export_dir = /srv/100%%\n")
          is_expected.to contain_file('/srv/100%').with(ensure: 'directory')
        end
      end

      context 'with only the vuls cassette, and no GMP password' do
        let(:params) { required.reject { |k, _| k == 'gmp_password' }.merge('vuls_cassette' => true, 'openvas_cassette' => false) }

        it { is_expected.to compile.with_all_deps }

        it 'removes any GMP credentials an earlier openvas cassette left behind' do
          is_expected.to contain_file("#{dir}/python/gvm-tools.conf").with_ensure('absent')
        end

        it 'has no host map, since only the openvas cassette writes addresses' do
          expect(config_ini).to match(%r{^host_map_file = $})
        end
      end

      context 'with the openvas cassette and no GMP password' do
        let(:params) { required.reject { |k, _| k == 'gmp_password' } }

        it { is_expected.to compile.and_raise_error(%r{set soundwave::gmp_password}) }
      end

      context "with the openvas module's observer user in Hiera, and no GMP settings for Soundwave" do
        let(:hiera_config) { 'spec/fixtures/hiera_observer/hiera.yaml' }
        let(:params) { required.reject { |k, _| k == 'gmp_password' } }

        it 'logs in as that user, with its password' do
          is_expected.to contain_file("#{dir}/python/gvm-tools.conf")
            .with_content(%r{^username = reader$}).with_content(%r{^password = observer-pw$})
        end
      end

      context 'outside a virtualenv' do
        let(:params) { required.merge('run_in_venv' => false) }

        it { is_expected.to compile.with_all_deps }
        it { is_expected.not_to contain_python__pyvenv('soundwave-env') }
        it { is_expected.to contain_python__requirements("#{dir}/python/requirements.txt").with_virtualenv('system') }
        it { expect(unit).to include('ExecStart=/usr/bin/python3 ') }
      end

      context 'with Python managed elsewhere' do
        let(:params) { required.merge('manage_python' => false, 'run_in_venv' => false) }

        # python::requirements includes the python class itself, so it is still
        # declared, with puppet-python's own defaults rather than these.
        it { is_expected.to compile.with_all_deps }
      end

      context 'with a named Python package' do
        let(:params) { required.merge('python_version' => 'python3.12') }

        it { is_expected.to contain_class('python').with_version('python3.12') }
      end


      context 'without pe_host, under a Puppet server' do
        let(:params) { required.reject { |k, _| k == 'pe_host' } }

        it 'pushes to the server that compiled the catalogue' do
          expect(config_ini).to match(%r{^host = \S+$})
          expect(config_ini).not_to include('host = pe.example.com')
        end
      end

      context 'with neither pe_token nor token_password' do
        let(:params) { required.reject { |k, _| k == 'pe_token' } }

        it { is_expected.to compile.and_raise_error(%r{set exactly one of soundwave::pe_token and soundwave::token_password}) }
      end

      context 'with both pe_token and token_password' do
        let(:params) { required.merge('token_password' => sensitive('pw')) }

        it { is_expected.to compile.and_raise_error(%r{set exactly one of soundwave::pe_token and soundwave::token_password}) }
      end

      context 'with token_password, so the node mints its own token' do
        # What node_encrypt::secret returns: ciphertext only this node can open.
        let(:params) do
          required.reject { |k, _| k == 'pe_token' }.merge('token_password' => RSpec::Puppet::RawString.new("Deferred('node_decrypt', ['CIPHERTEXT'])"))
        end
        let(:node) { 'scanner.example.com' }
        let(:token) { catalogue.resource('rbac_token', 'soundwave-scanner.example.com') }

        # rspec-puppet resolves Deferred values as an agent would, which needs
        # the node's key. Unresolved is the catalogue as the primary sends it.
        before(:each) { allow(Puppet::Pops::Evaluator::DeferredResolver).to receive(:resolve_and_replace) }

        it { is_expected.to compile.with_all_deps }

        it 'renews a 30-day token after 21 days into a root-only file, from the PE primary, before the service can run' do
          is_expected.to contain_rbac_token('soundwave-scanner.example.com').with(
            ensure: 'present', login: 'soundwave', lifetime: '30d', renew_after: '21d',
            token_file: "#{dir}/python/pe.token", server: 'pe.example.com', port: nil
          ).that_requires("File[#{dir}/python]").that_comes_before('Systemd::Timer[soundwave.timer]')
        end

        it 'passes the password through unresolved, so the catalogue carries only ciphertext' do
          expect(Puppet::Pops::Types::TypeFactory.deferred.instance?(token[:password])).to be(true)
          expect([token[:password].name, token[:password].arguments]).to eq(['node_decrypt', ['CIPHERTEXT']])
        end

        it 'points Soundwave at the token file and writes no token' do
          expect(config_ini).to include("token_file = #{dir}/python/pe.token\n")
          expect(config_ini).not_to match(%r{^token = })
        end

        context 'with everything named' do
          let(:params) do
            required.reject { |k, _| k == 'pe_token' }.merge(
              'token_password' => sensitive('pw'), 'token_login' => 'sw', 'token_file' => '/etc/soundwave.token',
              'token_lifetime' => '7d', 'token_renew_after' => '5d', 'token_server' => 'console.example.com', 'token_port' => 443
            )
          end

          it do
            is_expected.to contain_rbac_token('soundwave-scanner.example.com').with(
              login: 'sw', lifetime: '7d', renew_after: '5d', token_file: '/etc/soundwave.token', server: 'console.example.com', port: 443,
            )
          end

          it { expect(config_ini).to include("token_file = /etc/soundwave.token\n") }
        end

        context 'without conductor-rbac' do
          let(:params) { required.reject { |k, _| k == 'pe_token' }.merge('token_password' => sensitive('no-rbac')) }

          before(:each) do
            allow(Puppet::Pops::Evaluator::Runtime3ResourceSupport).to receive(:find_resource_type_or_class).and_call_original
            allow(Puppet::Pops::Evaluator::Runtime3ResourceSupport).to receive(:find_resource_type_or_class).with(anything, 'rbac_token').and_return(nil)
          end

          it { is_expected.to compile.and_raise_error(%r{token_password needs the rbac_token type from conductor-rbac}) }
        end
      end

      # rspec-puppet always sets server_facts, so the failure with neither
      # pe_host nor a server was proven with puppet apply instead (2026-11-09).
    end
  end
end
