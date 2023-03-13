#!/usr/bin/env ruby

require 'webdrivers'
require 'selenium-webdriver'

i = 0
image_paths = []

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

		image_path = 'webscreen/' + target.gsub('/', '_').gsub(':', '_').gsub('?', '_').gsub('\\', '_').gsub('*', '_').gsub('"', '_').gsub('<', '_').gsub('>', '_').gsub('|', '_').to_s + '.png'
		driver.save_screenshot(image_path)
		puts "[\e[34m" + i.to_s + "\e[0m] Screenshot saved as: #{image_path}"
		image_paths << image_path
			
	rescue
		
		puts "[\e[31m" + i.to_s + "\e[0m] ERROR while trying to take a screenshot of " + target
			
	end
		
end
	
driver.quit

# Create an HTML gallery with all the screenshots
File.open('gallery.html', 'w') do |html|
	html.write('<html><body><center>')
	
	image_paths.each do |path|
		html.write("<b>" + path.gsub('webscreen/', '_').gsub('__','://').gsub('.png','').gsub('_','') + "</b><br/><img src=\"#{path}\" width=\"600\"><br><br/><br/>")
	end
	
	html.write('</center></body></html>')
end
