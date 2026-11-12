# frozen_string_literal: true

require 'spec_helper'

# markdownlint only checks anchors inside one file, so a renamed heading would
# break a link to it from another page without failing anything else.
describe 'links in the README and the docs' do
  root = File.expand_path('../..', __dir__)
  slug = ->(heading) { heading.downcase.gsub(%r{[^\p{Word}\- ]}, '').tr(' ', '-') }
  anchors = ->(file) { File.read(file).then { |t| t.scan(%r{^#+ (.+)$}).flatten.map(&slug) + t.scan(%r{<a name="([^"]+)">}).flatten } }
  pages = [File.join(root, 'README.md')] + Dir[File.join(root, 'docs/**/*.md')]

  pages.each do |page|
    File.read(page).scan(%r{\]\(([^)\s]+)\)}).flatten.grep_v(%r{\A[a-z]+:}).each do |link|
      path, anchor = link.split('#', 2)
      target = path.empty? ? page : File.expand_path(path, File.dirname(page))

      it "#{page.delete_prefix("#{root}/")} links to #{link}, which exists" do
        expect(File.exist?(target) && (anchor.nil? || anchors.call(target).include?(anchor))).to be(true)
      end
    end
  end
end
