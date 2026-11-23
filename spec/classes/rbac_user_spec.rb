# frozen_string_literal: true

require 'spec_helper'

describe 'soundwave::rbac_user' do
  let(:facts) { { networking: { 'domain' => 'example.com', 'ip' => '172.16.254.254', 'fqdn' => 'primary.example.com' } } }
  # What node_encrypt::secret returns: ciphertext only the target node can open.
  let(:params) { { 'password' => RSpec::Puppet::RawString.new("Deferred('node_decrypt', ['CIPHERTEXT'])") } }

  # rspec-puppet resolves Deferred values the way an agent would, which needs
  # the node's private key. Leaving them unresolved shows the catalogue exactly
  # as the primary sends it.
  before(:each) { allow(Puppet::Pops::Evaluator::DeferredResolver).to receive(:resolve_and_replace) }

  it { is_expected.to compile.with_all_deps }

  it 'grants the role exactly what Soundwave does: register a transformer and push to VR' do
    is_expected.to contain_rbac_role('Soundwave').with(
      ensure: 'present',
      description: 'Soundwave vulnerability transformer: registers its transformer and pushes results to Vulnerability Remediation, nothing else',
      permissions: [
        { 'object_type' => 'premium_patching_vulnerability_management_transformers', 'action' => 'create', 'instance' => '*' },
        { 'object_type' => 'premium_patching_vulnerability_management_vulnerabilities', 'action' => 'create', 'instance' => '*' },
      ],
    )
  end

  it 'gives the user that role and nothing else' do
    is_expected.to contain_rbac_user('soundwave').with(
      ensure: 'present',
      display_name: 'Soundwave',
      email: 'soundwave@example.com',
      roles: ['Soundwave'],
      check_password: true,
    ).that_requires('Rbac_role[Soundwave]')
  end

  it 'hands the Deferred to the user unresolved, so the catalogue carries only ciphertext' do
    password = catalogue.resource('rbac_user', 'soundwave')[:password]
    expect(Puppet::Pops::Types::TypeFactory.deferred.instance?(password)).to be(true)
    expect([password.name, password.arguments]).to eq(['node_decrypt', ['CIPHERTEXT']])
  end

  context 'with everything named' do
    let(:params) do
      { 'password' => sensitive('pw'), 'login' => 'sw', 'role' => 'SW role', 'email' => 'sw@corp.example',
        'display_name' => 'SW', 'check_password' => false }
    end

    it { is_expected.to contain_rbac_role('SW role') }

    it do
      is_expected.to contain_rbac_user('sw').with(display_name: 'SW', email: 'sw@corp.example', roles: ['SW role'], check_password: false)
        .that_requires('Rbac_role[SW role]')
    end
  end

  context 'without conductor-rbac' do
    # Different inputs, or rspec-puppet hands back the catalogue it cached above.
    let(:params) { { 'password' => sensitive('pw'), 'login' => 'no-rbac' } }

    before(:each) do
      allow(Puppet::Pops::Evaluator::Runtime3ResourceSupport).to receive(:find_resource_type_or_class).and_call_original
      allow(Puppet::Pops::Evaluator::Runtime3ResourceSupport).to receive(:find_resource_type_or_class).with(anything, 'rbac_user').and_return(nil)
    end

    it { is_expected.to compile.and_raise_error(%r{needs the rbac_user and rbac_role types from conductor-rbac}) }
  end
end
