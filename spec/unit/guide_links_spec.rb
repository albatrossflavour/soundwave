# frozen_string_literal: true

require 'spec_helper'

# markdownlint only checks anchors inside one file, so a renamed heading would
# break a guide link to it without failing anything else.
describe 'links in the README and the install guide' do
  root = File.expand_path('../..', __dir__)
  slug = ->(heading) { heading.downcase.gsub(%r{[^\p{Word}\- ]}, '').tr(' ', '-') }
  pages = [File.join(root, 'README.md')] + Dir[File.join(root, 'docs/guide/*.md')]

  pages.each do |page|
    links = File.read(page).scan(%r{\]\(([^)\s]+)\)}).flatten.reject { |link| link.match?(%r{\A[a-z]+:}) }
    links.each do |link|
      it "#{page.delete_prefix("#{root}/")} links to #{link}" do
        path, anchor = link.split('#', 2)
        target = path.empty? ? page : File.expand_path(path, File.dirname(page))
        expect(File).to exist(target)
        expect(File.read(target).scan(%r{^#+ (.+)$}).flatten.map(&slug)).to include(anchor) if anchor
      end
    end
  end
end
