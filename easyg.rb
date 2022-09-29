#!/usr/bin/env ruby
#https://github.com/seeu-inspace/easyg/blob/main/easyg.rb

require 'webdrivers'
require 'selenium-webdriver'

puts "\e[35m\n 
███████╗ █████╗ ███████╗██╗   ██╗ ██████╗    ██████╗ ██████╗ 
██╔════╝██╔══██╗██╔════╝╚██╗ ██╔╝██╔════╝    ██╔══██╗██╔══██╗
█████╗  ███████║███████╗ ╚████╔╝ ██║  ███╗   ██████╔╝██████╔╝
██╔══╝  ██╔══██║╚════██║  ╚██╔╝  ██║   ██║   ██╔══██╗██╔══██╗
███████╗██║  ██║███████║   ██║   ╚██████╔╝██╗██║  ██║██████╔╝
╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝╚═╝  ╚═╝╚═════╝ 
\n\e[0m"

if ARGV[1] == "firefox"

	i = 0
	c = 0

	File.open(ARGV[0],'r').each_line do |f|
	
		target = f.gsub("\n","")
	
		i += 1
		
		puts "[\e[34m" + i.to_s + "\e[0m] Firefox open > " + target.to_s
		system 'start firefox "' + target.to_s + '"'
		
		c += 1
		
		if c >= 20
			sleep 30
			c = 0
		end
		
	end

end

if ARGV[1] == "crawl"

	File.open(ARGV[0],'r').each_line do |f|
	
		target = f.gsub("\n","")
		
		puts "[\e[34m+\e[0m] Crawling " + target.to_s + " with hakrawler" + "\n"
		system 'echo ' + target.to_s + '| hakrawler -u -insecure -t 20 -proxy http://localhost:8080'
		
		puts "[\e[34m+\e[0m] Crawling " + target.to_s + " with gospider" + "\n"
		system 'gospider -s "' + target.to_s + '" -c 10 -d 4 -t 20 --sitemap --other-source -p http://localhost:8080 --blacklist ".(svg|png|gif|ico|jpg|jpeg|bpm|mp3|mp4|ttf|woff|ttf2|woff2|eot|eot2|swf|swf2|css)"'
		
	end
end

if ARGV[1] == "webscreen"

	i = 0

	if File.directory?('webscreen') == false
		system "mkdir webscreen"
	end
	
	options = Selenium::WebDriver::Chrome::Options.new
	options.add_argument('--ignore-certificate-errors')
	options.add_argument('--disable-popup-blocking')
	options.add_argument('--disable-translate')
	options.add_argument('--ignore-certificate-errors-spki-list')

	driver = Selenium::WebDriver.for :chrome, options: options

	File.open(ARGV[0],'r').each_line do |f|
	
		target = f.gsub("\n","")
		
		i += 1

		begin
		
			driver.navigate.to target

			driver.save_screenshot('webscreen/' + target.gsub('/', '_').gsub(':', '_').gsub('?', '_').gsub('\\', '_').gsub('*', '_').gsub('"', '_').gsub('<', '_').gsub('>', '_').gsub('|', '_').to_s + '.png')
			puts "[\e[34m" + i.to_s + "\e[0m] Screenshot saved as: webscreen/" + target.gsub('/', '_').gsub(':', '_').gsub('?', '_').gsub('\\', '_').gsub('*', '_').gsub('"', '_').gsub('<', '_').gsub('>', '_').gsub('|', '_').to_s + '.png'
			
		rescue
		
			puts "[\e[31m" + i.to_s + "\e[0m] ERROR while trying to take a screenshot of " + target.to_s
			
		end
		
	end
	
	driver.quit
	
end

if ARGV[1] == "assetenum"

	if File.directory?('subdomains') == false
		system "mkdir subdomains"
	end
	
	if File.directory?('httprobe') == false
		system "mkdir httprobe"
	end

	File.open(ARGV[0],'r').each_line do |f|
	
		target = f.gsub("\n","")
		
		puts "\n[\e[34m+\e[0m] Enumerating subdomains for " + target.to_s + " with amass"
		system "amass enum -brute -active -d " + target.to_s + " -o subdomains/" + target.to_s + ".txt -v"

		puts "\n[\e[34m+\e[0m] Enumerating subdomains for " + target.to_s + " with subfinder"
		system "subfinder -d " + target.to_s + " -all -o subdomains/" + target.to_s + "_subfinder.txt"
		
		puts "\n[\e[34m+\e[0m] Adding new subdomains to " + target.to_s + ".txt with anew"
		system "type subdomains\\" + target.to_s + "_subfinder.txt | anew subdomains/" + target.to_s + ".txt"
		
		puts "\n[\e[34m+\e[0m] Enumerating subdomains for " + target.to_s + " with github-subdomains.py"
		system "python github-subdomains.py -t " + ARGV[2] + " -d " + target.to_s + " -e > subdomains/" + target.to_s + "_github.txt"
		
		puts "\n[\e[34m+\e[0m] Adding new subdomains to " + target.to_s + ".txt with anew"
		system "type subdomains\\" + target.to_s + "_github.txt | anew subdomains/" + target.to_s + ".txt"
		
		puts "\n[\e[34m+\e[0m] Results saved as subdomains/" + target.to_s + ".txt"
		
		puts "\n[\e[34m+\e[0m] Saving all results for " + ARGV[0] + " in subdomains/allsubs_" + ARGV[0]
		system "type subdomains\\" + target.to_s + " | anew subdomains/allsubs_" + ARGV[0]

	end
	
	puts "[\e[34m+\e[0m] Checking subdomains/allsubs_" + ARGV[0] + " with httprobe"
	system "type subdomains/allsubs_" + ARGV[0] + " | httprobe -p http:81 -p http:3000 -p https:3000 -p http:3001 -p https:3001 -p http:8000 -p http:8080 -p https:8443 -c 50 > httprobe/httprobed_" + ARGV[0]
	puts "[\e[34m+\e[0m] Results saved as httprobe/httprobed_" + ARGV[0]
	
end

if ARGV[0] == "help"

	puts "Usage: ruby easyg.rb <file_input> <option> \n\n"
	
	puts "options:"
	puts " firefox				open every entry in <file_input> with firefox"
	puts " crawl					crawl using as targets <file_input>"
	puts " webscreen				take a screenshot of every url in <file_input>"
	puts " assetenum <github_token>			subdomain discovery + httprobe + nuclei" + "\n\n"
	
	puts "Note: tested on Windows"
	
end
