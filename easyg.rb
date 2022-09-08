# https://github.com/seeu-inspace/easyg/blob/main/easyg.rb

require 'net/http'

$c = 0

$httprobe_config = "httprobe -p http:81 -p http:3000 -p https:3000 -p http:3001 -p https:3001 -p http:8000 -p http:8080 -p https:8443 -c 50"

puts "\e[35m\n E a s y G\n\e[0m"

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

	system "type " + file_i + " | " + $httprobe_config.to_s + " > httprobe/" + file_i +  "_httprobed"
	
end

def gau_go_on(file_i)

	system "type " + file_i + " | " + $httprobe_config.to_s + " | gau --o " + file_i + "_gau.txt --blacklist svg,png,gif,ico,jpg,bpm,mp3,mp4,ttf,woff,ttf2,woff2,eot,eot2,pptx,pdf,epub,docx,xlsx,css,txt --mc 200 --proxy http://localhost:8080"

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

if ARGV[1] == "firefox-httprobe"
	httprobe_go_on(ARGV[0])
	firefox_go_on(ARGV[0] + "_httprobed")
end

if ARGV[1] == "gau"
	gau_go_on(ARGV[0])
end

if ARGV[1] == "crawl"
	system "gospider -S " + ARGV[0] + " -o " + ARGV[0] + "_gospider -c 10 -d 1 -t 20 --sitemap --other-source --include-subs -p http://localhost:8080 --blacklist \".(svg|png|gif|ico|jpg|bpm|mp3|mp4|ttf|woff|ttf2|woff2|eot|eot2|pptx|pdf|epub|docx|xlsx|css|txt)\" "
	system "type " + ARGV[0] + " | hakrawler -subs -proxy http://localhost:8080 > " + ARGV[0] + "_hakrawler.txt"
end

if ARGV[1] == "paramspider"
	File.open(ARGV[0],'r').each_line do |f|
	begin
		target = f.gsub("\n","")
	end
		system "python paramspider.py --domain " + target.to_s + " --exclude svg,png,gif,ico,jpg,bpm,mp3,mp4,ttf,woff,ttf2,woff2,eot,eot2,pptx,pdf,epub,docx,xlsx,css,txt,js,axd --level high --output paramspider_results/" + target.to_s + ".txt"
		
		if File.exists?("paramspider_results/" + target.to_s + ".txt") == true
			system "type paramspider_results\\" + target.to_s + ".txt | anew paramspider_results/final.txt"
		end
		
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
	puts ' firefox-httprobe			open every entry in <file_input> with firefox checking them first with httprobe'
	puts ' gau					perform gau scan against the strings in the <file_input>'
	puts ' crawl					crawl using as targets <file_input>'
	puts ' paramspider				find parameters for every domain in <file_input>'
	puts ' amass <github_token>			subdomain discovery' + "\n\n"
	
	puts 'Note: tested on Windows'
	
end
