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
        it { is_expected.to contain_file("#{dir}/python/src").with(recurse: 'remote', purge: true, source: 'puppet:///modules/soundwave/python/src') }
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
          expect(unit).to end_with("ExecStart=#{dir}/python/env/bin/python3 #{dir}/python/src/soundwave.py\n")
        end

        it 'keeps the PE token and host in a root-only config' do
          is_expected.to contain_file("#{dir}/python/config.ini").with(owner: 'root', group: 'root', mode: '0600')
          expect(config_ini).to include("host = pe.example.com\n")
          expect(config_ini).to include("token = TOKEN\n")
        end

        it 'leaves the optional settings empty, which the Python reads as unset' do
          ['metrics_file', 'correlation_exceptions', 'findings_api_host', 'post_body_filepath', 'scan_name', 'host_map_file'].each do |key|
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

      context 'with only the vuls cassette, and no GMP password' do
        let(:params) { required.reject { |k, _| k == 'gmp_password' }.merge('vuls_cassette' => true, 'openvas_cassette' => false) }

        it { is_expected.to compile.with_all_deps }

        it 'removes any GMP credentials an earlier openvas cassette left behind' do
          is_expected.to contain_file("#{dir}/python/gvm-tools.conf").with_ensure('absent')
        end
      end

      context 'with the openvas cassette and no GMP password' do
        let(:params) { required.reject { |k, _| k == 'gmp_password' } }

        it { is_expected.to compile.and_raise_error(%r{set soundwave::gmp_password}) }
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

      # rspec-puppet always sets server_facts, so the failure with neither
      # pe_host nor a server was proven with puppet apply instead (2026-11-09).
    end
  end
end
