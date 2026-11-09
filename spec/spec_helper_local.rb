# frozen_string_literal: true

RSpec.configure do |c|
  c.after(:suite) do
    # Every resource the module declares has a spec, and it stays that way.
    RSpec::Puppet::Coverage.report!(100)
  end
end
