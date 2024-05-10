#!/usr/bin/env ruby

require 'uri'
require 'net/http'
require 'json'
require 'socket'
require 'webdrivers'
require 'selenium-webdriver'



def logo
	result = ""
	lines = [ "\n███████╗ █████╗ ███████╗██╗   ██╗ ██████╗    ██████╗ ██████╗ ",
		    "██╔════╝██╔══██╗██╔════╝╚██╗ ██╔╝██╔════╝    ██╔══██╗██╔══██╗",
		    "█████╗  ███████║███████╗ ╚████╔╝ ██║  ███╗   ██████╔╝██████╔╝",
		    "██╔══╝  ██╔══██║╚════██║  ╚██╔╝  ██║   ██║   ██╔══██╗██╔══██╗",
		    "███████╗██║  ██║███████║   ██║   ╚██████╔╝██╗██║  ██║██████╔╝",
		    "╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝    ╚═════╝ ╚═╝╚═╝  ╚═╝╚═════╝ ",
	]

	lines.each do |line|
		line.each_char.with_index do |char, i|
			shade = (i / 8) % 8 + 44
			result += "\e[38;5;#{shade}m#{char}\e[0m"
		end
		result += "\n"
	end

	puts result
	
	message = "└──────────────[~] Made with <3 by Riccardo Malatesta (@seeu)"
	message.chars.each_with_index do |char, index|
		shade = (index / 8) % 8 + 44
		print "\e[38;5;#{shade}m#{char}\e[0m"
		sleep(0.01) 
	end
	
	puts "\n\n"
	
end

puts logo

print "\e[93m┌─\e[0m Enter an option [help, firefox, gettoburp, assetenum, webscreenshot, crawl-burp]:\n\e[93m└─\e[0m "
option = gets.chomp

if option == "assetenum"
	print "\e[93m┌─\e[0m Heavy mode? [y/n]:\n\e[93m└─\e[0m "
	gb_opt = gets.chomp
	
	print "\e[93m┌─\e[0m Give a GitHub token for github-subdomains:\n\e[93m└─\e[0m "
	gh_tok = gets.chomp
end

if option == "firefox" || option == "gettoburp" || option == "assetenum" || option == "webscreenshot" || option == "crawl-burp"
	print "\e[93m┌─\e[0m Enter the file target:\n\e[93m└─\e[0m "
	file = gets.chomp
end

puts "\n"

def adding_anew(file_tmp,file_final)
	system "cat " + file_tmp.gsub('/','/') + " | anew " + file_final
	File.delete(file_tmp) if File.exists? file_tmp
end


def delete_if_empty(file)

	if File.zero?(file)
		puts "[\e[36m+\e[0m] No result found"
		File.delete(file) if File.exists?(file)
	else
		puts "[\e[36m+\e[0m] Results added at " + file
	end
	
end

def request_fun(uri)
	
	proxy_host = '127.0.0.1'
	proxy_port = '8080'
	
	headers = {
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0",
		"Cookie": "0=1",
		"Authorization": "0=1"
	}
	
	ssl_options = {
		:use_ssl => true,
		:verify_mode => OpenSSL::SSL::VERIFY_NONE
	}

	res = nil
	req = Net::HTTP::Get.new(uri.request_uri, headers)
	
	Net::HTTP.start(uri.host, uri.port, proxy_host, proxy_port, ssl_options) do |http|
		res = http.request(req)
	end

	return res

end


if option == "firefox"

	i = 0

	File.open(file,'r').each_line do |f|
	
		target = f.gsub("\n","").to_s
		
		i += 1
	
		puts "[\e[36m#{i.to_s}\e[0m] Firefox open > " + target
		system 'firefox "' + target + '"'
				
		sleep 30 if i%20==0
		
	end

end


if option == "gettoburp"
	
	i = 0
	
	File.open(file,'r').each_line do |f|
		begin
		
			redirect = 2
		
			res = request_fun(URI.parse(f.gsub("\n","").to_s))
			
			puts "[\e[36m#{i.to_s}\e[0m] GET > " + f.gsub("\n","").to_s
			i += 1
			
			while res.is_a?(Net::HTTPRedirection) && redirect > 0
				puts "    Redirecting to > " + res['location'].to_s
				res = request_fun(URI.parse(res['location']))
				redirect -= 1
			end

		rescue Exception => e
			puts "[\e[31m+\e[0m] ERROR: " + e.message
		end
	end

end


if option == "assetenum"

	system "mkdir output" if File.directory?('output') == false
	
	File.open(file,'r').each_line do |f|
	 
		target = f.gsub("\n","").to_s
		
		#== amass ==
		
		if gb_opt == "y"
			puts "\n[\e[36m+\e[0m] Enumerating subdomains for " + target + " with amass"
			system "amass enum -brute -active -d " + target + " -v -dns-qps 200"
			system "oam_subs -names -d " + target + " > output/" + target + "_tmp.txt"
		end
		
		if gb_opt == "n"
			puts "\n[\e[36m+\e[0m] Enumerating subdomains for " + target + " with amass"
			system "amass enum -passive -d " + target + " -v -timeout 15 -dns-qps 200"
			system "oam_subs -names -d " + target + " > output/" + target + "_tmp.txt"
		end

		#== subfinder ==
		puts "\n[\e[36m+\e[0m] Enumerating subdomains for " + target + " with subfinder"
		system "subfinder -d " + target + " -all -o output/" + target + "_subfinder.txt"
		
		adding_anew("output/" + target + "_subfinder.txt", "output/" + target + "_tmp.txt")
		
		#== github-subdomains ==
		puts "\n[\e[36m+\e[0m] Enumerating subdomains for " + target + " with github-subdomains"
		system "github-subdomains -t #{gh_tok} -d " + target + " -o output/" + target + "_github.txt"
		
		adding_anew("output/" + target + "_github.txt", "output/" + target + "_tmp.txt")
		
		#== crt.sh ==
		puts "\n[\e[36m+\e[0m] Enumerating subdomains for " + target + " with crt.sh"
		
		begin
			uri = URI.parse("https://crt.sh/?q=" + target + "&output=json")
			response = Net::HTTP.get_response(uri)
			crtsh = JSON.parse((response.body).to_s)

			crtsh_o = File.new("output/" + target + "_crtsh.txt", "w")

			crtsh.each do | f |
				puts f["common_name"].gsub('*.','').to_s
				if f.include? "." + target
					crtsh_o.puts f["common_name"].gsub('*.','').to_s
				end
			end

			crtsh_o.close unless crtsh_o.nil? or crtsh_o.closed?
			
			adding_anew("output/" + target + "_crtsh.txt", "output/" + target + "_tmp.txt")
			
		rescue Exception => e
			puts "[\e[31m+\e[0m] ERROR: " + e.message
		end
		
		#== gobuster ==
		
		if gb_opt == "y"
		
			if !File.exists? "all.txt"
				uri = URI.parse("https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt")
				response = Net::HTTP.get_response(uri)
				alltxt = (response.body).to_s
				File.open('all.txt', 'w') { |file| file.write(alltxt) }
			end
		
			puts "\n[\e[34m+\e[0m] Enumerating subdomains for " + target + " with gobuster and all.txt"
			system "gobuster dns -d " + target + " -v -t 250 --no-color --wildcard -o output/" + target + "_gobuster_tmp.txt -w all.txt"

			gobuster_o = File.new("output/" + target + "_gobuster.txt", 'w')
			gobuster_tmp = File.open("output/" + target + "_gobuster_tmp.txt",'r')

			gobuster_tmp.each_line do |f|
				if f.include? "Found: "
					gobuster_o.puts f.gsub("Found: ","")
				end
			end

			gobuster_tmp.close unless gobuster_tmp.nil? or gobuster_tmp.closed?
			File.delete("output/" + target + "_gobuster_tmp.txt") if File.exists? "output/" + target + "_gobuster_tmp.txt"
			
			gobuster_o.close unless gobuster_o.nil? or gobuster_o.closed?
			adding_anew("output/" + target + "_gobuster.txt", "output/" + target + "_tmp.txt")

		end
		
		#== anew final ==
		
		puts "\n[\e[36m+\e[0m] Checking if IPs for the subdomains of " + target + " exist"
		
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

		puts "[\e[36m+\e[0m] Results for " + target + " saved as output/" + target + ".txt"
		
		puts "\n[\e[36m+\e[0m] Adding the results for " + target + " to output/allsubs_" + file
		system "cat output/" + target + ".txt | anew output/allsubs_" + file
		puts "[\e[36m+\e[0m] Results for " + file + " saved as output/allsubs_" + file

	end
	
	#== httpx ==
	puts "\n[\e[36m+\e[0m] Checking output/allsubs_" + file + " with httpx"
	system "cat output/allsubs_" + file + " | httpx-toolkit -p 80,443,81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3001,3002,3003,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9092,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672 -o output/httpx_" + file
	puts "[\e[36m+\e[0m] Results saved as output/httpx_" + file
	
	#== naabu ==
	if gb_opt == "y"
		puts "\n[\e[36m+\e[0m] Searching for more open ports in output/allsubs_" + file + " with naabu"
		system "naabu -v -list output/allsubs_" + file + " -p - -exclude-ports 80,443,81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3001,3002,3003,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9092,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672 -c 1000 -rate 7000 -stats -o output/naabu_" + file
		delete_if_empty "output/naabu_" + file
	end
	
	#== naabu | httpx ==
	if File.exists? "output/naabu_" + file
		puts "\n[\e[36m+\e[0m] Checking for hidden web ports in output/naabu_" + file
		system "cat output/naabu_" + file + " | httpx-toolkit -o output/httpx_naabu_" + file
		
		if File.exists? "output/httpx_naabu_" + file
			system "cat output/httpx_naabu_" + file
			adding_anew("output/httpx_naabu_" + file, "output/httpx_" + file)
			puts "[\e[36m+\e[0m] Results added at output/httpx_" + file
		end
	end
	
	#== interesting subs ==
	
	puts "\n[\e[36m+\e[0m] Showing some interesting subdomains found"
	system "cat output/allsubs_" + file + " | grep -E \"jenkins|jira|gitlab|github|sonar|bitbucket|travis|circleci|eslint|pylint|junit|testng|pytest|jest|selenium|appium|postman|newman|cypress|seleniumgrid|artifactory|nexus|ansible|puppet|chef|deploybot|octopus|prometheus|grafana|elk|slack|teams\" | sort -u > output/interesting_subdomains_" + file
	system "cat output/interesting_subdomains_" + file
	delete_if_empty "output/interesting_subdomains_" + file
	
	#== nuclei ==	
	puts "\n[\e[36m+\e[0m] Checking with nuclei in " + file
	system "nuclei -l output/httpx_" + file + " -t ~/.local/nuclei-templates/takeovers -t ~/.local/nuclei-templates/exposures/configs/git-config.yaml -t ~/.local/nuclei-templates/vulnerabilities/generic/crlf-injection.yaml -t ~/.local/nuclei-templates/exposures/apis/swagger-api.yaml -t ~/.local/nuclei-templates/misconfiguration/put-method-enabled.yaml -stats -o output/nuclei_" + file
	delete_if_empty "output/nuclei_" + file
	
end


if option == "webscreenshot"

	urls = File.readlines(file).map(&:chomp)

	i = 0
	image_paths = []

	system "mkdir output" if !File.directory?('output')
	system "mkdir output/webscreen" if !File.directory?('output/webscreen')

	options = Selenium::WebDriver::Chrome::Options.new
	options.add_argument('--ignore-certificate-errors')
	options.add_argument('--disable-popup-blocking')
	options.add_argument('--disable-translate')
	options.add_argument('--ignore-certificate-errors-spki-list')
	options.add_argument('--headless')

	driver = Selenium::WebDriver.for :chrome, options: options

	urls.each do |url|
		i += 1

		begin
			driver.navigate.to url

			image_path = "output/webscreen/#{url.gsub(/[^\w\s]/, '_')}.png"
			driver.save_screenshot(image_path)
			puts "[\e[34m#{i}\e[0m] Screenshot saved as: #{image_path}"
			image_paths << image_path
		rescue Exception => e
			puts "[\e[31m#{i}\e[0m] ERROR while trying to take a screenshot of #{url}: #{e.message}"
		end
	end

	driver.quit

	# Create an HTML gallery with all the screenshots
	File.open('output/gallery.html', 'w') do |html|
		html.write('<!DOCTYPE html>')
		html.write('<html lang="en">')
		html.write('<head>')
		html.write('<meta charset="UTF-8">')
		html.write('<meta name="viewport" content="width=device-width, initial-scale=1.0">')
		html.write('<title>Web Screenshots Gallery</title>')
		html.write('<style>')
		html.write('body { font-family: Arial, sans-serif; background-color: #1e2227; color: #fff; }')
		html.write('.container { max-width: 800px; margin: 0 auto; }')
		html.write('.screenshot { margin-bottom: 20px; border: 2px solid white; background-color: #fff; color: #1e2227; }')
		html.write('.screenshot img { max-width: 100%; display: block; margin: 0 auto; transition: box-shadow 0.3s; }')
		html.write('.screenshot img:hover { box-shadow: 0 0 2px 1px rgba(0, 140, 186, 0.5); }')
		html.write('.screenshot-url { font-size: 14px; margin-top: 5px; text-align: center; }')
		html.write('</style>')
		html.write('</head>')
		html.write('<body>')
		html.write('<div class="container">')

		image_paths.each_with_index do |path, index|
			html.write('<div class="screenshot">')
			html.write("<img src=\"#{path.gsub('output/', '')}\" alt=\"Screenshot #{index + 1}\">")
			html.write("<div class=\"screenshot-url\"><b>URL:</b> <a href=\"#{urls[index]}\" target=_blank>#{urls[index]}</a></div>")
			html.write('</div>')
		end

		html.write('</div>')
		html.write('</body>')
		html.write('</html>')
	end

end


if option == "crawl-burp"

	File.open(file,'r').each_line do |f|
		target = f.gsub("\n","").to_s
		
		puts "[\e[34m+\e[0m] Crawling " + target + " with hakrawler" + "\n"
		system 'echo ' + target + '| hakrawler -u -insecure -t 20 -proxy http://localhost:8080 -h "Cookie: 0=1;;Authorization: Basic MD0x"'
		
		puts "[\e[34m+\e[0m] Crawling " + target + " with gospider" + "\n"
		system 'gospider -s "' + target + '" -c 10 -d 4 -t 20 --sitemap --other-source -p http://localhost:8080 -H "Cookie: 0=1" -H "Authorization: Basic MD0x" --blacklist ".(svg|png|gif|ico|jpg|jpeg|bpm|mp3|mp4|ttf|woff|ttf2|woff2|eot|eot2|swf|swf2|css)"'
		
		puts "[\e[34m+\e[0m] Crawling " + target + " with katana" + "\n"
		system 'katana -u "' + target + '" -jc -kf -aff -proxy http://127.0.0.1:8080 -H "Cookie: 0=1"'
		
		puts "[\e[34m+\e[0m] Crawling " + target + " with gau" + "\n"
		system 'echo ' + target + '| gau --blacklist svg,png,gif,ico,jpg,jpeg,bpm,mp3,mp4,ttf,woff,ttf2,woff2,eot,eot2,swf,swf2,css --fc 404 --proxy http://localhost:8080'
		
	end
	
end


if option == "help"

	puts "Options"
	puts "	firefox					open every entry in <file_input> with firefox"
	puts "	gettoburp				for every entry in <file_input> send a GET request"
	puts "	assetenum				asset enumeration, use gb as option to also use gobuster"
	puts "	webscreenshot				take a screenshot for every entry in <file_input> and make a gallery"
	puts "	crawl-burp				crawl for every entry in <file_input> and pass the results to Burp Suite port 8080"
	puts "	help\n\n"
	

end
