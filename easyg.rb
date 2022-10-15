#!/usr/bin/env ruby
#https://github.com/seeu-inspace/easyg/blob/main/easyg.rb


require 'webdrivers'
require 'selenium-webdriver'
require 'net/http'
require 'uri'
require 'json'


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
	
		target = f.gsub("\n","").to_s
	
		i += 1
		
		puts "[\e[34m" + i.to_s + "\e[0m] Firefox open > " + target
		system 'start firefox "' + target + '"'
		
		c += 1
		
		if c >= 20
			sleep 30
			c = 0
		end
		
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
	
end

if ARGV[1] == "crawl"

	File.open(ARGV[0],'r').each_line do |f|
	
		target = f.gsub("\n","").to_s
		
		puts "[\e[34m+\e[0m] Crawling " + target + " with hakrawler" + "\n"
		system 'echo ' + target + '| hakrawler -u -insecure -t 20 -proxy http://localhost:8080'
		
		puts "[\e[34m+\e[0m] Crawling " + target + " with gospider" + "\n"
		system 'gospider -s "' + target + '" -c 10 -d 4 -t 20 --sitemap --other-source -p http://localhost:8080 --blacklist ".(svg|png|gif|ico|jpg|jpeg|bpm|mp3|mp4|ttf|woff|ttf2|woff2|eot|eot2|swf|swf2|css)"'
		
	end
end

if ARGV[1] == "assetenum"

	if File.directory?('subdomains') == false
		system "mkdir subdomains"
	end
	
	if File.directory?('httprobe') == false
		system "mkdir httprobe"
	end
	
	if File.directory?('nuclei') == false
		system "mkdir nuclei"
	end
	
	if File.directory?('naabu') == false
		system "mkdir naabu"
	end

	File.open(ARGV[0],'r').each_line do |f|
	
		target = f.gsub("\n","").to_s
		
		#== amass ==
		puts "\n[\e[34m+\e[0m] Enumerating subdomains for " + target + " with amass"
		system "amass enum -brute -active -d " + target + " -o subdomains/" + target + ".txt -v"

		#== subfinder ==
		puts "\n[\e[34m+\e[0m] Enumerating subdomains for " + target + " with subfinder"
		system "subfinder -d " + target + " -all -o subdomains/" + target + "_subfinder.txt"
		puts "\n[\e[34m+\e[0m] Adding new subdomains to subdomains/" + target + ".txt with anew"
		system "type subdomains\\" + target + "_subfinder.txt | anew subdomains/" + target + ".txt"
		
		#== github-subdomains ==
		puts "\n[\e[34m+\e[0m] Enumerating subdomains for " + target + " with github-subdomains"
		system "github-subdomains -t github-token.txt -d " + target + " -o subdomains/" + target + "_github.txt"
		puts "\n[\e[34m+\e[0m] Adding new subdomains to subdomains/" + target + ".txt with anew"
		system "type subdomains\\" + target + "_github.txt | anew subdomains/" + target + ".txt"
		
		#== gobuster + all.txt ==
		puts "\n[\e[34m+\e[0m] Enumerating subdomains for " + target + " with gobuster and all.txt"
		system "gobuster dns -domain " + target + " -v -t 50 -o subdomains/" + target + "_gobuster_tmp.txt -w all.txt"
		
		gobuster_o = File.new("subdomains/" + target + "_gobuster.txt", 'w')
		gobuster_tmp = File.open("subdomains/" + target + "_gobuster_tmp.txt",'r')
		
		gobuster_tmp.each_line do |f|
			if f.include? "Found: "
				gobuster_o.puts f.gsub("Found: ","")
			end
		end
		
		gobuster_tmp.close unless gobuster_tmp.nil? or gobuster_tmp.closed?
		File.delete("subdomains/" + target + "_gobuster_tmp.txt") if File.exists? "subdomains/" + target + "_gobuster_tmp.txt"
		gobuster_o.close unless gobuster_o.nil? or gobuster_o.closed?
		
		File.delete("subdomains/" + target + "_gobuster_tmp.txt")
		
		puts "\n[\e[34m+\e[0m] Adding new subdomains to subdomains/" + target + ".txt with anew"
		system "type subdomains\\" + target + "_gobuster.txt | anew subdomains/" + target + ".txt"

		#== crt.sh ==
		puts "\n[\e[34m+\e[0m] Enumerating subdomains for " + target + " with crt.sh"
		uri = URI.parse("https://crt.sh/?q=" + target + "&output=json")
		response = Net::HTTP.get_response(uri)
		crtsh = JSON.parse((response.body).to_s)

		crtsh_o = File.new("subdomains/" + target + "_crtsh.txt", "w")

		crtsh.each do | f |
			puts f["common_name"].gsub('*.','').to_s
			crtsh_o.puts f["common_name"].gsub('*.','').to_s
		end

		crtsh_o.close unless crtsh_o.nil? or crtsh_o.closed?

		puts "\n[\e[34m+\e[0m] Adding new subdomains to subdomains/" + target + ".txt with anew"
		system "type subdomains\\" + target + "_crtsh.txt | anew subdomains/" + target + ".txt"
		
		#== anew final ==
		puts "\n[\e[34m+\e[0m] Results saved as subdomains/" + target + ".txt"
		puts "\n[\e[34m+\e[0m] Saving all results for " + ARGV[0] + " in subdomains/allsubs_" + ARGV[0]
		system "type subdomains\\" + target + ".txt | anew subdomains/allsubs_" + ARGV[0]

	end
	
	#== httprobe ==
	puts "[\e[34m+\e[0m] Checking subdomains/allsubs_" + ARGV[0] + " with httprobe"
	system "type subdomains\\allsubs_" + ARGV[0] + " | httprobe -p http:81 -p http:3000 -p https:3000 -p http:3001 -p https:3001 -p http:8000 -p http:8080 -p https:8443 -c 150 > httprobe/httprobed_" + ARGV[0]
	puts "[\e[34m+\e[0m] Results saved as httprobe/httprobed_" + ARGV[0]
	
	#== nuclei ==
	puts "[\e[34m+\e[0m] Checking for exposed .git and takeovers with nuclei in" + ARGV[0]
	system "nuclei -l httprobe/httprobed_" + ARGV[0] + " -t %USERPROFILE%/nuclei-templates/takeovers -t %USERPROFILE%/nuclei-templates/exposures/configs/git-config.yaml -o nuclei/nuclei_" + ARGV[0]
	puts "[\e[34m+\e[0m] Results saved as nuclei/nuclei_" + ARGV[0]
	
	#== naabu ==
	puts "[\e[34m+\e[0m] Searching for more open ports in subdomains/allsubs_" + ARGV[0] + " with naabu"
	system "naabu -v -list subdomains/allsubs_" + ARGV[0] + " -exclude-ports 80,443,81,3000,3001,8000,8080,8443 -c 1000 -rate 7000 -stats -o naabu/naabu_" + ARGV[0]
	puts "[\e[34m+\e[0m] Results saved as naabu/naabu_" + ARGV[0]
	
	#== naabu | httprobe ==
	puts "[\e[34m+\e[0m] Checking for hidden web ports in naabu/naabu_" + ARGV[0]
	system "type naabu\\naabu_" + ARGV[0] + " | httprobe > naabu/naabu_httprobe_" + ARGV[0]
	puts "[\e[34m+\e[0m] Results saved as naabu/naabu_httprobe_" + ARGV[0]
	
end

if ARGV[0] == "help"

	puts "Usage: ruby easyg.rb <file_input> <option> \n\n"
	
	puts "Options"
	puts "	firefox					open every entry in <file_input> with firefox"
	puts "	webscreen				take a screenshot of every url in <file_input>"
	puts "	crawl					crawl using as targets <file_input>"
	puts "	assetenum				subdomain discovery + httprobe + naabu + nuclei"
	puts "	help\n\n"
	
	puts "Notes 
	create a file called github-token.txt with your github token
	tested on Windows"

end
