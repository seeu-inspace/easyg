#!/usr/bin/env ruby
#https://github.com/seeu-inspace/easyg/blob/main/easyg.rb


require 'webdrivers'
require 'selenium-webdriver'
require 'uri'
require 'net/http'
require 'json'
require 'socket'


puts "\e[36m\n 
███████╗ █████╗ ███████╗██╗   ██╗ ██████╗    ██████╗ ██████╗ 
██╔════╝██╔══██╗██╔════╝╚██╗ ██╔╝██╔════╝    ██╔══██╗██╔══██╗
█████╗  ███████║███████╗ ╚████╔╝ ██║  ███╗   ██████╔╝██████╔╝
██╔══╝  ██╔══██║╚════██║  ╚██╔╝  ██║   ██║   ██╔══██╗██╔══██╗
███████╗██║  ██║███████║   ██║   ╚██████╔╝██╗██║  ██║██████╔╝
╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝╚═╝  ╚═╝╚═════╝ 
                   Made with <3 by Riccardo Malatesta (@seeu)
\n\e[0m"


def adding_anew(file_tmp,file_final)
	system "type " + file_tmp.gsub('/','\\') + " | anew " + file_final
	File.delete(file_tmp) if File.exists? file_tmp
end

def delete_if_empty(file)

	if File.zero?(file)
		puts "[\e[34m+\e[0m] No result found"
		File.delete(file) if File.exists?(file)
	else
		puts "[\e[34m+\e[0m] Results added at " + file
	end
	
end

if ARGV[1] == "firefox"

	i = 0

	File.open(ARGV[0],'r').each_line do |f|
	
		target = f.gsub("\n","").to_s
		
		i += 1
	
		puts "[\e[34m" + i.to_s + "\e[0m] Firefox open > " + target
		system 'start firefox "' + target + '"'
				
		if i%20==0
			sleep 30
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
		system 'echo ' + target + '| hakrawler -u -insecure -t 20 -proxy http://localhost:8080 -h "Cookie: 0=1"'
		
		puts "[\e[34m+\e[0m] Crawling " + target + " with gospider" + "\n"
		system 'gospider -s "' + target + '" -c 10 -d 4 -t 20 --sitemap --other-source -p http://localhost:8080 --cookie "0=1" --blacklist ".(svg|png|gif|ico|jpg|jpeg|bpm|mp3|mp4|ttf|woff|ttf2|woff2|eot|eot2|swf|swf2|css)"'
		
	end
end

if ARGV[1] == "assetenum"

	if File.directory?('output') == false
		system "mkdir output"
	end

	File.open(ARGV[0],'r').each_line do |f|
	
		target = f.gsub("\n","").to_s
		
		#== amass ==
		puts "\n[\e[34m+\e[0m] Enumerating subdomains for " + target + " with amass"
		system "amass enum -brute -active -d " + target + " -o output/" + target + "_tmp.txt -v"

		#== subfinder ==
		puts "\n[\e[34m+\e[0m] Enumerating subdomains for " + target + " with subfinder"
		system "subfinder -d " + target + " -all -o output/" + target + "_subfinder.txt"
		
		adding_anew("output/" + target + "_subfinder.txt", "output/" + target + "_tmp.txt")
		
		#== github-subdomains ==
		puts "\n[\e[34m+\e[0m] Enumerating subdomains for " + target + " with github-subdomains"
		system "github-subdomains -t github-token.txt -d " + target + " -o output/" + target + "_github.txt"
		
		adding_anew("output/" + target + "_github.txt", "output/" + target + "_tmp.txt")
		
		#== crt.sh ==
		puts "\n[\e[34m+\e[0m] Enumerating subdomains for " + target + " with crt.sh"
		
		begin
			uri = URI.parse("https://crt.sh/?q=" + target + "&output=json")
			response = Net::HTTP.get_response(uri)
			crtsh = JSON.parse((response.body).to_s)

			crtsh_o = File.new("subdomains/" + target + "_crtsh.txt", "w")

			crtsh.each do | f |
				puts f["common_name"].gsub('*.','').to_s
				crtsh_o.puts f["common_name"].gsub('*.','').to_s
			end

			crtsh_o.close unless crtsh_o.nil? or crtsh_o.closed?
			
			adding_anew("output/" + target + "_crtsh.txt", "output/" + target + "_tmp.txt")
			
		rescue
			puts "[\e[31m+\e[0m] ERROR while trying to retrieve information from crt.sh"
		end
		
		#== anew final ==
		
		puts "\n[\e[34m+\e[0m] Checking if IPs for the subdomains of " + target + " exist"
		
		allsubs_final = File.new("output/" + target + ".txt", 'w')
		allsubs_tmp = File.open("output/" + target + "_tmp.txt",'r')

		allsubs_tmp.each_line do |line|
			begin
				ip=IPSocket::getaddress(line.strip)
			rescue
				ip="unknown"
			end

			if ip!="unknown"
				puts line
				allsubs_final.puts line
			end
			
		end

		allsubs_tmp.close unless allsubs_tmp.nil? or allsubs_tmp.closed?
		File.delete("output/" + target + "_tmp.txt") if File.exists? "output/" + target + "_tmp.txt"
		allsubs_final.close unless allsubs_final.nil? or allsubs_final.closed?

		puts "[\e[34m+\e[0m] Results for " + target + " saved as output/" + target + ".txt"
		
		puts "\n[\e[34m+\e[0m] Adding the results for " + target + " to output/allsubs_" + ARGV[0]
		system "type output\\" + target + ".txt | anew output/allsubs_" + ARGV[0]
		puts "[\e[34m+\e[0m] Results for " + ARGV[0] + " saved as output/allsubs_" + ARGV[0]

	end
	
	#== httprobe ==
	puts "[\e[34m+\e[0m] Checking output/allsubs_" + ARGV[0] + " with httprobe"
	system "type output\\allsubs_" + ARGV[0] + " | httprobe -p http:81 -p http:3000 -p https:3000 -p http:3001 -p https:3001 -p http:8000 -p http:8080 -p https:8443 -c 150 > output/httprobe_" + ARGV[0] + " && type output\\httprobe_" + ARGV[0]
	puts "[\e[34m+\e[0m] Results saved as output/httprobe_" + ARGV[0]
	
	#== naabu ==
	puts "[\e[34m+\e[0m] Searching for more open ports in output/allsubs_" + ARGV[0] + " with naabu"
	system "naabu -v -list output/allsubs_" + ARGV[0] + " -exclude-ports 80,443,81,3000,3001,8000,8080,8443 -c 1000 -rate 7000 -stats -o output/naabu_" + ARGV[0]
	delete_if_empty "output/naabu_" + ARGV[0]
	
	#== naabu | httprobe ==
	if File.exists? "output/naabu_" + ARGV[0]
		puts "[\e[34m+\e[0m] Checking for hidden web ports in naabu/naabu_" + ARGV[0]
		system "type output\\naabu_" + ARGV[0] + " | httprobe > output/httprobe_naabu_" + ARGV[0] + " && type output\\httprobe_naabu_" + ARGV[0]
		delete_if_empty "naabu/httprobe_naabu_" + ARGV[0]
	end
	
	#== nuclei ==
	puts "[\e[34m+\e[0m] Checking for exposed .git and takeovers with nuclei in " + ARGV[0]
	system "nuclei -l output/httprobe_" + ARGV[0] + " -t %USERPROFILE%/nuclei-templates/takeovers -t %USERPROFILE%/nuclei-templates/exposures/configs/git-config.yaml -t %USERPROFILE%/nuclei-templates/vulnerabilities/generic/crlf-injection.yaml -t %USERPROFILE%/nuclei-templates/exposures/apis/swagger-api.yaml -o output/nuclei_" + ARGV[0]
	delete_if_empty "output/nuclei_" + ARGV[0]
	
	#== check for log4j ==
	puts "[\e[34m+\e[0m] Checking for log4j in " + ARGV[0]
	system "nuclei -l output/httprobe_" + ARGV[0] + " -as -tags log4j -o output/nuclei_log4j_" + ARGV[0]
	delete_if_empty "output/log4j_" + ARGV[0]
	
end

if ARGV[0] == "help"

	puts "Usage: ruby easyg.rb <file_input> <option> \n\n"
	
	puts "Options"
	puts "	firefox					open every entry in <file_input> with firefox"
	puts "	webscreen				take a screenshot of every url in <file_input>"
	puts "	crawl					crawl using as targets <file_input>"
	puts "	assetenum				asset enumeration & co."
	puts "	help\n\n"
	
	puts "Notes 
	create a file called github-token.txt with your github token in the same dir of easyg
	tested on Windows, change 'type' with 'cat'"

end
