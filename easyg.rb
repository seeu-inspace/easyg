# https://github.com/seeu-inspace/easyg/blob/main/easyg.rb

require 'webdrivers'
require 'selenium-webdriver'

$c = 0

$httprobe_config = "httprobe -p http:81 -p http:3000 -p https:3000 -p http:3001 -p https:3001 -p http:8000 -p http:8080 -p https:8443 -c 50"

puts "\e[35m\n 
███████╗ █████╗ ███████╗██╗   ██╗ ██████╗    ██████╗ ██████╗ 
██╔════╝██╔══██╗██╔════╝╚██╗ ██╔╝██╔════╝    ██╔══██╗██╔══██╗
█████╗  ███████║███████╗ ╚████╔╝ ██║  ███╗   ██████╔╝██████╔╝
██╔══╝  ██╔══██║╚════██║  ╚██╔╝  ██║   ██║   ██╔══██╗██╔══██╗
███████╗██║  ██║███████║   ██║   ╚██████╔╝██╗██║  ██║██████╔╝
╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝╚═╝  ╚═╝╚═════╝ 
\n\e[0m"

def sleep_f()

	$c += 1
	
	if $c >= 15
		sleep 30
		$c = 0
	end
	
end

def firefox_go_on(file_i)

	i = 0

	File.open(file_i,'r').each_line do |f|
	begin
		target = f.gsub("\n","")
	end
		i += 1
		puts '[' + i.to_s + '] Firefox open > ' + target.to_s
		system 'start firefox "' + target.to_s + '"'
		
		sleep_f()
	end

end

def httprobe_go_on(file_i)

	if File.directory?('httprobe') == false
		system "mkdir httprobe"
	end	
	
	puts "[+] Scan of " + file_i + " with httprobe"
	
	system "type " + file_i + " | " + $httprobe_config.to_s + " > httprobe/" + file_i +  "_httprobed"
	
end

# === OPTIONS ===

if ARGV[1] == "nmap"
	system "nmap -p 1-65535 -T4 -A -v -Pn -sV -iL " + ARGV[0] + " -oX " + ARGV[0] +  ".xml"
end

if ARGV[1] == "firefox"
	firefox_go_on(ARGV[0])
end

if ARGV[1] == "httprobe"
	httprobe_go_on(ARGV[0])
end

if ARGV[1] == "crawl"
	File.open(ARGV[0],'r').each_line do |f|
	begin
		target = f.gsub("\n","")
	end
	
		puts "[+] Crawling " + target.to_s

		system 'gospider -s "' + target.to_s + '" -c 10 -d 1 -t 20 --sitemap --other-source -p http://localhost:8080 --blacklist ".(svg|png|gif|ico|jpg|jpeg|bpm|mp3|mp4|ttf|woff|ttf2|woff2|eot|eot2|swf|swf2|pptx|pdf|epub|docx|xlsx|css|txt)" '
		system 'echo ' + target.to_s + '| hakrawler -proxy http://localhost:8080'
		system 'echo ' + target.to_s + '| gau --blacklist svg,png,gif,ico,jpg,jpeg,bpm,mp3,mp4,ttf,woff,ttf2,woff2,eot,eot2,swf,swf2,pptx,pdf,epub,docx,xlsx,css,txt --mc 200 --proxy http://localhost:8080'
		
	end
end

if ARGV[1] == "paramspider"
	File.open(ARGV[0],'r').each_line do |f|
	begin
		target = f.gsub("\n","")
	end
		system "python ../ParamSpider/paramspider.py --domain " + target.to_s + " --exclude svg,png,gif,ico,jpg,jpeg,bpm,mp3,mp4,ttf,woff,ttf2,woff2,eot,eot2,swf,swf2,pptx,pdf,epub,docx,xlsx,css,txt,js,axd --level high --output paramspider_results/" + target.to_s + ".txt"

		if File.exists?("paramspider_results/" + target.to_s + ".txt") == true
			system "type paramspider_results\\" + target.to_s + ".txt | anew paramspider_results/final.txt"
		end
	end
end

if ARGV[1] == "webscreen"

	File.open(ARGV[0],'r').each_line do |f|
	begin
		target = f.gsub("\n","")
	end
		driver = Selenium::WebDriver.for :chrome
		driver.navigate.to target
		
		if File.directory?('webscreen') == false
			system "mkdir webscreen"
		end

		puts '[+] Screenshot saved as: webscreen/' + ((target.gsub('//', '')).gsub('/', '_').gsub(':', '_')).to_s + '.png' 

		driver.save_screenshot('webscreen/' + (((target.gsub('/', '_')).gsub(':', '_')).gsub('?', '_')).to_s + '.png')

		driver.quit
	end
end

if ARGV[1] == "amass"

	File.open(ARGV[0],'r').each_line do |f|
	begin
		target = f.gsub("\n","")
	end
		
		system "amass enum -brute -active -d " + target.to_s + " -o subdomains/" + target.to_s + ".txt"

		system "subfinder -d " + target.to_s + " -all -o subdomains/" + target.to_s + "_subfinder.txt"
		
		system "type subdomains\\" + target.to_s + "_subfinder.txt | anew subdomains/" + target.to_s + ".txt"
		
		puts "\n[+] Enumerating subdomains for " + target.to_s + " with github-subdomains.py"
		
		system "python github-subdomains.py -t " + ARGV[2] + " -d " + target.to_s + " -e > subdomains/" + target.to_s + "_github.txt"
		
		system "type subdomains\\" + target.to_s + "_github.txt | anew subdomains/" + target.to_s + ".txt"

	end
	
end

if ARGV[0] == "help"

	puts 'Usage: ruby easyg.rb <file_input> <option>'+ "\n\n"
	puts 'options:'
	puts ' nmap					perform nmap scan against the domains in the <file_input>'
	puts ' firefox				open every entry in <file_input> with firefox'
	puts ' httprobe				check every entry in <file_input> with httprobe'
	puts ' crawl					crawl using as targets <file_input>'
	puts ' paramspider				find parameters for every domain in <file_input>'
	puts ' webscreen				take a screenshot of every url in <file_input>'
	puts ' amass <github_token>			subdomain discovery' + "\n\n"
	
	puts 'Note: tested on Windows'
	
end
