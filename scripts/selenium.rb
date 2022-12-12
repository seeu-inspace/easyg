#!/usr/bin/env ruby
require 'webdrivers'
require 'selenium-webdriver'

i = 0

system "mkdir webscreen" if File.directory?('webscreen') == false
	
options = Selenium::WebDriver::Chrome::Options.new
options.add_argument('--ignore-certificate-errors')
options.add_argument('--disable-popup-blocking')
options.add_argument('--disable-translate')
options.add_argument('--ignore-certificate-errors-spki-list')

driver = Selenium::WebDriver.for :chrome, options: options

File.open(ARGV[0],'r').each_line do |f|
	
	target = f.gsub("\n","").to_s
		
	i += 1

	begin
		
		driver.navigate.to target

		driver.save_screenshot('webscreen/' + target.gsub('/', '_').gsub(':', '_').gsub('?', '_').gsub('\\', '_').gsub('*', '_').gsub('"', '_').gsub('<', '_').gsub('>', '_').gsub('|', '_').to_s + '.png')
		puts "[\e[34m" + i.to_s + "\e[0m] Screenshot saved as: webscreen/" + target.gsub('/', '_').gsub(':', '_').gsub('?', '_').gsub('\\', '_').gsub('*', '_').gsub('"', '_').gsub('<', '_').gsub('>', '_').gsub('|', '_').to_s + '.png'
			
	rescue
		
		puts "[\e[31m" + i.to_s + "\e[0m] ERROR while trying to take a screenshot of " + target
			
	end
		
end
	
driver.quit
