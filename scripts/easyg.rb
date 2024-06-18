#!/usr/bin/env ruby

require 'uri'
require 'net/http'
require 'json'
require 'socket'
require 'webdrivers'
require 'selenium-webdriver'
require 'yaml'

$config = YAML.load_file('config.yaml')

# =========================
# ======= FUNCTIONS =======
# =========================

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



def adding_anew(file_tmp, file_final)
	system "cat #{file_tmp} | anew #{file_final}"
	File.delete(file_tmp) if File.exists?(file_tmp)
end



def urless_fun(file_i, file_o)
	system "urless -i #{file_i} -o #{file_o}"
	File.delete(file_i) if File.exists?(file_i)
end


def delete_if_empty(file)
	if File.zero?(file) || !File.exists?(file)
		puts "[\e[36m+\e[0m] No result found"
		File.delete(file) if File.exists?(file)
	else
		puts "[\e[36m+\e[0m] Results added at #{file}"
	end
end



def request_fun(uri)

	proxy_host = $config['proxy_addr']
	proxy_port = $config['proxy_port']

	headers = {
		"User-Agent" => $config['user-agent'],
		"Cookie" => $config['cookie'],
		"Authorization" => $config['authorization']
	}

	ssl_options = {
		:use_ssl => true,
		:verify_mode => OpenSSL::SSL::VERIFY_NONE
	}

	res = nil
	req = Net::HTTP::Get.new(uri.request_uri, headers)

	Net::HTTP.start(uri.host, uri.port, proxy_host, proxy_port, ssl_options) do |http|
		http.open_timeout = 5
		http.read_timeout = 5
		res = http.request(req)
	end

	return res

end



def get_content_type(url)
	begin
		uri = URI.parse(url)
		response = nil

		limit = 3
		while limit > 0
			response = Net::HTTP.get_response(uri)

			case response
			when Net::HTTPRedirection then
				uri = URI.parse(response['location'])
			else
				break
			end

			limit -= 1
		end

		if response.is_a?(Net::HTTPSuccess)
			return response['content-type']
		else
			return nil
		end

	rescue => e
		return nil
	end
end



def replace_param_with_fuzz(url)
	uri = URI.parse(url)
	params = URI.decode_www_form(uri.query || '')
	params.map! { |param, value| [param, 'FUZZ'] }
	uri.query = URI.encode_www_form(params)
	uri.to_s
end



def process_file_with_sed(file_path)
	unless File.exists?(file_path)
		puts "[\e[31m+\e[0m] File not found: #{file_path}"
		return
	end

	sed_command = "sed -r -i -e 's/\\x1B\\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g' #{file_path}"

	unless system(sed_command)
		puts "[\e[31m+\e[0m] Error processing file"
	end
end



def encode_component(component)
	component.gsub(/%[0-9A-Fa-f]{2}/) { |match| match }.split(/(%[0-9A-Fa-f]{2})/).map { |segment| segment.match?(/%[0-9A-Fa-f]{2}/) ? segment : URI.encode_www_form_component(segment).gsub('%', '%25') }.join
end



def sanitize_url(url)
	uri = URI.parse(url)

	encoded_path = uri.path.split('/').map { |segment| encode_component(segment) }.join('/')
	encoded_query = uri.query ? uri.query.split('&').map { |param| param.split('=', 2).map { |part| encode_component(part) }.join('=') }.join('&') : nil
	encoded_fragment = uri.fragment ? encode_component(uri.fragment) : nil

	begin
		URI::Generic.build(
			scheme: uri.scheme,
			userinfo: uri.user,
			host: uri.host,
			port: uri.port,
			path: encoded_path,
			query: encoded_query,
			fragment: encoded_fragment
		).to_s
	rescue => e
		return nil
	end

end



def file_sanitization(file_path)
	unless File.exists?(file_path)
		puts "[\e[31m+\e[0m] File not found: #{file_path}"
		return
	end

	sanitized_lines = []

	File.foreach(file_path) do |line|
		line.strip!
		if line.start_with?("http")
			begin
				sanitized_lines << sanitize_url(line)
			rescue URI::InvalidURIError
				puts "[\e[31m+\e[0m] Invalid URL found and skipped: #{line}"
			end
		else
			sanitized_lines << line
		end
	end

	File.write(file_path, sanitized_lines.join("\n") + "\n")
end



def waf_check(target)
	output = "wafw00f \"#{target}\" -v"
	if output.include?("is behind a")
		yield target
	else
		puts "[\e[31m+\e[0m] Skipped, the target is behind a WAF"
	end
end



def check_url(url)
	uri = URI.parse(url)
	response = nil
	Net::HTTP.start(uri.host, uri.port, use_ssl: uri.scheme == 'https') do |http|
		request = Net::HTTP::Get.new(uri)
		response = http.request(request)
	end
	response
rescue => e
	puts "[\e[31m+\e[0m] Error checking URL #{url}: #{e.message}"
	nil
end



# Get a file containing URLs, check for their status code with check_url
# If the status code is the one desired, creates a new file containing the results
def process_urls_for_code(file_to_scan, output_file, status_code)
	File.open(output_file, 'w') do |output|
		File.foreach(file_to_scan) do |url|
			url.strip!
			next if url.empty?
			response = check_url(url)
			if response && response.code.to_i == status_code
				output.puts(url)
				puts url
			end
		end
	end
end



def remove_using_scope(scope_file, url_file)
	scope_urls = File.readlines(scope_file).map(&:strip)
	urls = File.readlines(url_file).map(&:strip)
	
	scope_hosts = scope_urls.map { |url| URI(url).host }

	filtered_urls = urls.select do |url|
		begin
			url_host = URI(url).host
			scope_hosts.any? { |scope_host| url_host.end_with?(scope_host) }
		rescue
			puts "[\e[31m+\e[0m] Invalid URL found and skipped: #{url}"
		end
	end

	File.open(url_file, 'w') do |file|
		filtered_urls.each { |url| file.puts(url) }
	end
end



def search_confidential_files(file_type, file_to_scan)
	puts "\n[\e[36m+\e[0m] Searching for possible confidential #{file_type.upcase}s"
	
	# Define the regex pattern based on the file type
	regex_pattern = case file_type
					when 'pdf' then '\\.pdf'
					when 'txt' then '\\.txt'
					when 'csv' then '\\.csv'
					else return
					end

	output_file = "output/reserved#{file_type.upcase}s_#{file_to_scan.gsub("/", "")}"

	# Construct the command to search for confidential files
	command = <<~BASH
		for i in `cat #{file_to_scan} | grep -Ea '#{regex_pattern}'`; do
			if curl -s "$i" | #{file_type == 'pdf' ? 'pdftotext -q - - | ' : ''}grep -Eaiq 'internal use only|usage interne uniquement|confidential|confidentielle|password|credentials'; then
				echo $i | tee -a #{output_file};
			fi;
		done
	BASH

	system(command)
	delete_if_empty(output_file)
end



def search_for_vulns(params)

	file_to_scan = params[:file]

	system "mkdir output" if File.directory?('output') == false

	o_sanitized = file_to_scan.gsub(/[^\w\s]/, '_')
	file_sanitization file_to_scan

	# Get only 200s
	process_urls_for_code(file_to_scan, "output/200_#{o_sanitized}.txt", 200)

	# :: Search for possible confidential files ::
	['pdf', 'txt', 'csv', 'xml'].each do |file_type|
		search_confidential_files(file_type, "output/200_#{o_sanitized}.txt")
	end

	# :: Mantra ::
	puts "\n[\e[36m+\e[0m] Searching for API keys with Mantra"
	system "cat output/200_#{o_sanitized}.txt | mantra -t 20 | grep -Ev \"Unable to make a request for|Regex Error|Unable to read the body of\" | tee output/mantra_results_#{o_sanitized}.txt"
	delete_if_empty "output/mantra_results_#{o_sanitized}.txt"
	process_file_with_sed "output/mantra_results_#{o_sanitized}.txt"

	# :: SocialHunter
	puts "\n[\e[36m+\e[0m] Searching for Brojen Link Hijaking with socialhunter"
	system "socialhunter -f output/200_#{o_sanitized}.txt -w 20 | grep \"Possible Takeover\" | tee output/socialhunter_results_#{o_sanitized}.txt"
	delete_if_empty "output/socialhunter_results_#{o_sanitized}.txt"

	if params[:gb_opt] == "y"

		## :: Grep only params ::
		system "cat #{file_to_scan} | grep \"?\" | tee output/allParams_#{o_sanitized}.txt"
		# Read each URL from the file, replace parameter values with FUZZ, and overwrite the file with the modified URLs
		File.open("output/allParams_#{o_sanitized}.txt", 'r+') do |file|
			lines = file.readlines.map(&:strip)
			file.rewind
			file.truncate(0)
			lines.each do |line|
				begin
				modified_url = replace_param_with_fuzz(line)
				file.puts modified_url
				rescue Exception => e
					puts "[\e[31m+\e[0m] ERROR: #{e.message}"
				end
			end
		end

		# Search for XSS and LFI
		puts "\n[\e[36m+\e[0m] Searching for XSSs and LFIs"
		process_urls_for_code("output/allParams_#{o_sanitized}.txt", "output/200allParams_#{o_sanitized}.txt", 200)
		File.open("output/200allParams_#{o_sanitized}.txt",'r').each_line do |f|

			target = f.chomp
			sanitized_target = target.gsub(/[^\w\s]/, '_')
			content_type = get_content_type(target)

			if content_type && content_type.include?('text/html')
				system "dalfox url \"#{target}\" -C \"#{$config['cookie']}\" --only-poc r --ignore-return 302,404,403 --waf-evasion -o output/dalfox/#{sanitized_target}.txt"
			end

			waf_check(target) do |t|
				system "ffuf -u \"#{t}\" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -ac -mc 200 -od output/ffuf_lfi/#{sanitized_target}/"
			end

		end
		puts "[\e[36m+\e[0m] Results saved in the directories output/dalfox/ and output/ffuf_lfi/" if File.directory?('output/dalfox/') || File.directory?('output/ffuf_lfi/')

		# Search for Open Redirects
		puts "\n[\e[36m+\e[0m] Searching for Open Redirects"
		process_urls_for_code("output/allParams_#{o_sanitized}.txt", "output/302allParams_#{o_sanitized}.txt", 302)
		File.open("output/302allParams_#{o_sanitized}.txt",'r').each_line do |f|
			target = f.chomp
			sanitized_target = target.gsub(/[^\w\s]/, '_')
			waf_check(target) do |t|
				system "python3 ~/Tools/web-attack/Oralyzer/oralyzer.py -u \"#{t}\" -p /usr/share/seclists/Payloads/Open-Redirect/Open-Redirect-payloads.txt >> output/redirect_#{o_sanitized}.txt"
			end
		end
		process_file_with_sed "output/redirect_#{o_sanitized}.txt"
		puts "[\e[36m+\e[0m] Results saved in the directory output/redirect_#{o_sanitized}.txt" if File.exists?("output/redirect_#{o_sanitized}.txt")

	end

end



# :: Functions for the options ::



def show_help(option_actions)
	# Calculate the maximum length of the option names
	max_option_length = option_actions.keys.max_by(&:length).length

	option_actions.each do |option, info|
		# Calculate the padding needed to align descriptions
		padding = " " * (max_option_length - option.length + 12)

		# Print the option name, description, and padding
		puts "\t#{option}#{padding}#{info[:description]}"
	end
end



def firefox_fun(params)
	i = 0
	File.open(params[:file],'r').each_line do |f|
		target = f.chomp
		i += 1
		puts "[\e[36m#{i.to_s}\e[0m] Firefox open > #{target}"
		system "firefox \"#{target}\""
		sleep 30 if i%20==0
	end
end



def get_to_burp_fun(params)

	i = 0

	File.open(params[:file],'r').each_line do |f|

		i += 1

		begin

			redirect = 2

			res = request_fun(URI.parse(f.chomp))

			puts "[\e[36m#{i.to_s}\e[0m] GET > #{f.chomp}"

			while res.is_a?(Net::HTTPRedirection) && redirect > 0
				puts "	Redirecting to > #{res['location'].to_s}"
				res = request_fun(URI.parse(res['location']))
				redirect -= 1
			end

		rescue Net::OpenTimeout, Net::ReadTimeout => e
			puts "[\e[31m+\e[0m] TIMEOUT ERROR: #{e.message}"
		rescue StandardError => e
			puts "[\e[31m+\e[0m] ERROR: #{e.message}"
		end
		
	end

end



def assetenum_fun(params)

	file = params[:file]

	system "mkdir output" if File.directory?('output') == false

	File.open(file,'r').each_line do |f|

		target = f.chomp

		#== amass ==

		if params[:gb_opt] == "y"
			puts "\n[\e[36m+\e[0m] Enumerating subdomains for #{target} with amass"
			system "amass enum -brute -active -d #{target} -v -dns-qps 200"
			system "oam_subs -names -d #{target} | tee output/#{target}_tmp.txt"
		else
			puts "\n[\e[36m+\e[0m] Enumerating subdomains for #{target} with amass"
			system "amass enum -passive -d #{target} -v -timeout 15 -dns-qps 200"
			system "oam_subs -names -d #{target} | tee output/#{target}_tmp.txt"
		end

		#== subfinder ==
		puts "\n[\e[36m+\e[0m] Enumerating subdomains for #{target} with subfinder"
		system "subfinder -d #{target} -all -o output/#{target}_subfinder.txt"

		adding_anew("output/#{target}_subfinder.txt", "output/#{target}_tmp.txt")

		#== github-subdomains ==
		if $config['github_token'] != nil || $config['github_token'] != "YOUR_GITHUB_TOKEN_HERE"
			puts "\n[\e[36m+\e[0m] Enumerating subdomains for #{target} with github-subdomains"
			system "github-subdomains -t #{$config['github_token']} -d #{target} -o output/#{target}_github.txt"
			adding_anew("output/#{target}_github.txt", "output/#{target}_tmp.txt")
		end

		#== crt.sh ==
		puts "\n[\e[36m+\e[0m] Enumerating subdomains for #{target} with crt.sh"

		begin
			uri = URI.parse("https://crt.sh/?q=#{target}&output=json")
			response = Net::HTTP.get_response(uri)
			crtsh = JSON.parse((response.body).to_s)

			crtsh_o = File.new("output/#{target}_crtsh.txt", "w")

			crtsh.each do | f |
				if !f["common_name"].nil?
					puts f["common_name"].gsub('*.','').to_s
					if f.include? ".#{target}"
						crtsh_o.puts f["common_name"].gsub('*.','').to_s
					end
				end
			end

			crtsh_o.close unless crtsh_o.nil? or crtsh_o.closed?

			adding_anew("output/#{target}_crtsh.txt", "output/#{target}_tmp.txt")
			File.delete("output/#{target}_crtsh.txt") if File.exists?("output/#{target}_crtsh.txt")

		rescue Exception => e
			puts "[\e[31m+\e[0m] ERROR: #{e.message}"
		end

		#== gobuster ==

		if params[:gb_opt] == "y"

			if !File.exists?("all.txt")
				uri = URI.parse("https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt")
				response = Net::HTTP.get_response(uri)
				alltxt = (response.body).to_s
				File.open('all.txt', 'w') { |file| file.write(alltxt) }
			end

			puts "\n[\e[36m+\e[0m] Enumerating subdomains for #{target} with gobuster and all.txt"
			system "gobuster dns -d #{target} -v -t 250 --no-color --wildcard -o output/#{target}_gobuster_tmp.txt -w all.txt"

			gobuster_o = File.new("output/#{target}_gobuster.txt", 'w')
			gobuster_tmp = File.open("output/#{target}_gobuster_tmp.txt",'r')

			gobuster_tmp.each_line do |f|
				if f.include? "Found: "
					gobuster_o.puts f.gsub("Found: ","")
				end
			end

			gobuster_tmp.close unless gobuster_tmp.nil? or gobuster_tmp.closed?
			File.delete("output/#{target}_gobuster_tmp.txt") if File.exists?("output/#{target}_gobuster_tmp.txt")

			gobuster_o.close unless gobuster_o.nil? or gobuster_o.closed?
			adding_anew("output/#{target}_gobuster_tmp.txt", "output/#{target}_gobuster_tmp.txt")

		end

		#== anew final ==

		puts "\n[\e[36m+\e[0m] Checking if IPs for the subdomains of #{target} exist"

		allsubs_final = File.new("output/#{target}.txt", 'w')
		allsubs_tmp = File.open("output/#{target}_tmp.txt",'r')

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
		File.delete("output/#{target}_tmp.txt") if File.exists?("output/#{target}_tmp.txt")
		allsubs_final.close unless allsubs_final.nil? or allsubs_final.closed?

		puts "[\e[36m+\e[0m] Results for #{target} saved as output/#{target}.txt"

		puts "\n[\e[36m+\e[0m] Adding the results for #{target} to output/allsubs_#{file}"
		adding_anew("output/#{target}.txt","output/allsubs_#{file}")
		puts "[\e[36m+\e[0m] Results for #{file} saved as output/allsubs_#{file}"

	end

	#== httpx ==
	puts "\n[\e[36m+\e[0m] Searching for web services output/allsubs_#{file}"
	system "cat output/allsubs_#{file} | httpx-toolkit -p 80,443,81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3001,3002,3003,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9092,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672 -o output/http_#{file}"
	system "cat output/allsubs_#{file} | httprobe -p http:81 -p http:3000 -p https:3000 -p http:3001 -p https:3001 -p http:8000 -p http:8080 -p https:8443 -c 50 | anew output/http_#{file}"
	puts "[\e[36m+\e[0m] Results saved as output/http_#{file}"

	#== naabu ==
	if params[:gb_opt] == "y"
		puts "\n[\e[36m+\e[0m] Searching for more open ports in output/allsubs_#{file} with naabu"
		system "naabu -v -list output/allsubs_#{file} -p - -exclude-ports 80,443,81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3001,3002,3003,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9092,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672 -c 1000 -rate 7000 -stats -o output/naabu_#{file}"
		delete_if_empty "output/naabu_#{file}"
	end

	#== naabu | httpx ==
	if File.exists?("output/naabu_#{file}")
		puts "\n[\e[36m+\e[0m] Checking for hidden web ports in output/naabu_#{file}"
		system "cat output/naabu_#{file} | httpx-toolkit -o output/http_naabu_#{file}"
		system "cat output/naabu_#{file} | httprobe | anew output/http_naabu_#{file}"

		if File.exists?("output/http_naabu_#{file}")
			system "cat output/http_naabu_#{file}"
			adding_anew("output/http_naabu_#{file}", "output/http_#{file}")
			puts "[\e[36m+\e[0m] Results added at output/http_#{file}"
		end
	end

	# == Interesting subs ==

	puts "\n[\e[36m+\e[0m] Showing some interesting subdomains found"
	system "cat output/allsubs_#{file} | grep -E \"jenkins|jira|gitlab|github|sonar|bitbucket|travis|circleci|eslint|pylint|junit|testng|pytest|jest|selenium|appium|postman|newman|cypress|seleniumgrid|artifactory|nexus|ansible|puppet|chef|deploybot|octopus|prometheus|grafana|elk|slack|admin|geoservice|teams\" | sort -u | tee output/interesting_subdomains_#{file}"
	system "cat output/http_#{file} | grep -E \"jenkins|jira|gitlab|github|sonar|bitbucket|travis|circleci|eslint|pylint|junit|testng|pytest|jest|selenium|appium|postman|newman|cypress|seleniumgrid|artifactory|nexus|ansible|puppet|chef|deploybot|octopus|prometheus|grafana|elk|slack|admin|geoservice|teams\" | sort -u | anew output/interesting_subdomains_#{file}"
	delete_if_empty "output/interesting_subdomains_#{file}"

	# == Search for vulns ==
	if params[:vl_opt] == "y"
		# Use some Nuclei templates
		puts "\n[\e[36m+\e[0m] Checking with nuclei in #{file}"
		system "nuclei -l output/http_#{file} -t ~/.local/nuclei-templates/http/takeovers -t ~/.local/nuclei-templates/http/exposures/configs/git-config.yaml -t ~/.local/nuclei-templates/dast/vulnerabilities/crlf/crlf-injection.yaml -t ~/.local/nuclei-templates/http/exposures/apis/swagger-api.yaml -t ~/.local/nuclei-templates/http/misconfiguration/put-method-enabled.yaml -stats -o output/nuclei_#{file}"
		delete_if_empty "output/nuclei_#{file}"

		# Search for 401 and 403 bypasses
		puts "\n[\e[36m+\e[0m] Searching for 401,403 and bypasses #{file}"
		process_urls_for_code("output/http_#{file}", "output/40X_#{file}", 403)
		process_urls_for_code("output/http_#{file}", "output/401_#{file}", 401)
		system "cat output/401_#{file} >> output/40X_#{file} && rm output/401_#{file}"
		system "byp4xx -xD -xE -xX -m 2 -L output/40X_#{file} | grep -v '==' |tee output/byp4xx_results_#{file}"
		system "dirsearch -e * -x 404,403,401,429 -l output/40X_#{file}.txt --no-color --full-url -o output/dirsearch_results_40X_#{file}"
		delete_if_empty "output/byp4xx_results_#{file}"
		process_file_with_sed "output/byp4xx_results_#{file}"
	end

end



def webscreenshot_fun(params)

	urls = File.readlines(params[:file]).map(&:chomp)

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
		html.write('<title>EasyG Web Screenshots Gallery</title>')
		html.write('<style>')
		html.write('.screenshot { margin: 5px; border: 1px solid #ccc; float: left; width: 180px; }')
		html.write('.screenshot:hover { border: 1px solid #777; }')
		html.write('.screenshot img { width: 100%; height: auto; }')
		html.write('.screenshot-desc { padding: 15px; text-align: center; }')
		html.write('</style>')
		html.write('</head>')
		html.write('<body>')

		image_paths.each_with_index do |path, index|
			html.write('<div class="screenshot">')
			html.write("<a href=\"#{path.gsub('output/', '')}\" target=_blank>")
			html.write("<img src=\"#{path.gsub('output/', '')}\" alt=\"Screenshot #{urls[index]}\"  width=\"600\" height=\"400\">")
			html.write("</a>")
			html.write("<div class=\"screenshot-desc\"><b>URL:</b> <a href=\"#{urls[index]}\" target=_blank>#{urls[index]}</a></div>")
			html.write('</div>')
		end

		html.write('</body>')
		html.write('</html>')
	end

end



def crawl_burp_fun(params)

	File.open(params[:file],'r').each_line do |f|
		target = f.chomp

		puts "\n[\e[36m+\e[0m] Crawling #{target} with hakrawler\n"
		system 'echo ' + target + "| hakrawler -u -insecure -t 20 -proxy http://#{$config['proxy_addr']}:#{$config['proxy_port']} -h \"Cookie: #{$config['cookie']};;Authorization: #{$config['authorization']}\""

		puts "\n[\e[36m+\e[0m] Crawling #{target} with gospider\n"
		system 'gospider -s "' + target + "\" -c 10 -d 4 -t 20 --sitemap --other-source -p http://#{$config['proxy_addr']}:#{$config['proxy_port']} -H \"Cookie: #{$config['cookie']}\" -H \"Authorization: #{$config['authorization']}\" --blacklist \".(svg|png|gif|ico|jpg|jpeg|bpm|mp3|mp4|ttf|woff|ttf2|woff2|eot|eot2|swf|swf2|css)\""

		puts "\n[\e[36m+\e[0m] Crawling #{target} with katana\n"
		system 'katana -u "' + target + "\" -jc -jsl -hl -kf -aff -d 3 -fs rdn -proxy http://#{$config['proxy_addr']}:#{$config['proxy_port']} -H \"Cookie: #{$config['cookie']}\""

		puts "\n[\e[36m+\e[0m] Crawling #{target} with gau\n"
		system 'echo ' + target + "| gau --blacklist svg,png,gif,ico,jpg,jpeg,bpm,mp3,mp4,ttf,woff,ttf2,woff2,eot,eot2,swf,swf2,css --fc 404 --threads 5 --proxy http://#{$config['proxy_addr']}:#{$config['proxy_port']}"

	end

end



def crawl_local_fun(params)

	file = params[:file]
	file_sanitized = file.gsub("/", "")
	target_tmp = ""

	system "mkdir output" if File.directory?('output') == false

	File.open(file,'r').each_line do |f|
		target = f.chomp
		target_sanitized = target.gsub(/^https?:\/\//, '').gsub(/:\d+$/, '').gsub('/','')
		target_tmp = ""

		puts "\n[\e[36m+\e[0m] Crawling #{target} with katana\n"
		system "katana -u #{target} -jc -jsl -hl -kf -aff -H \"Cookie: #{$config['cookie']}\" -d 3 -fs fqdn -o output/#{target_sanitized}_tmp.txt"
		
		puts "\n[\e[36m+\e[0m] Finding more endpoints for #{target} with waymore\n"
		system "waymore -i #{target} -c /home/kali/.config/waymore/config.yml --no-subs -f -p 5 -mode U -oU output/#{target_sanitized}_waymore.txt"
		adding_anew("output/#{target_sanitized}_waymore.txt", "output/#{target_sanitized}_tmp.txt")

		puts "\n[\e[36m+\e[0m] Crawling #{target} with gau\n"
		system 'echo ' + target + "| gau --blacklist svg,png,gif,ico,jpg,jpeg,bpm,mp3,mp4,ttf,woff,ttf2,woff2,eot,eot2,swf,swf2,css --fc 404 --o output/#{target_sanitized}_gau.txt"
		adding_anew("output/#{target_sanitized}_gau.txt", "output/#{target_sanitized}_tmp.txt")

		if target_sanitized != target_tmp
			puts "\n[\e[36m+\e[0m] Finding more endpoints for #{target_sanitized} with ParamSpider\n"
			system "paramspider -d #{target_sanitized}"
		end
		target_tmp = target_sanitized

		adding_anew("results/#{target_sanitized}.txt", "output/#{target_sanitized}_tmp.txt")
		system "sed -i -E '/^(http|https):/!d' output/#{target_sanitized}_tmp.txt"
		urless_fun("output/#{target_sanitized}_tmp.txt", "output/#{target_sanitized}_urless.txt")
		adding_anew("output/#{target_sanitized}_urless.txt","output/_tmpAllUrls_#{file_sanitized}")
		puts "[\e[36m+\e[0m] Results for #{target} saved in output/_tmpAllUrls_#{file_sanitized}"
	end

	system "rm -rf results/"

	# JS file analysis
	puts "\n[\e[36m+\e[0m] Searching for JS files"
	system "cat output/_tmpAllUrls_#{file_sanitized} | grep '\\.js$' | tee output/_tmp1AllJSUrls_#{file_sanitized}"
	system "cat output/_tmpAllUrls_#{file_sanitized} | subjs | anew output/_tmp1AllJSUrls_#{file_sanitized}"
	urless_fun("output/_tmp1AllJSUrls_#{file_sanitized}","output/_tmpAllJSUrls_#{file_sanitized}")
	system "cat output/_tmpAllJSUrls_#{file_sanitized} | anew output/_tmpAllUrls_#{file_sanitized}"

	# Just keep it 200 for JS files
	process_urls_for_code("output/_tmpAllJSUrls_#{file_sanitized}", "output/allJSUrls_#{file_sanitized}", 200)
	remove_using_scope(file, "output/allJSUrls_#{file_sanitized}")
	File.delete("output/_tmpAllJSUrls_#{file_sanitized}") if File.exists?("output/_tmpAllJSUrls_#{file_sanitized}")
	puts "[\e[36m+\e[0m] Results saved as output/allJSUrls_#{file_sanitized}"

	# Find new URLs from the JS files
	puts "\n[\e[36m+\e[0m] Finding more endpoints from output/allJSUrls_#{file_sanitized} with xnLinkFinder"
	system "sed -E 's~^[a-zA-Z]+://([^:/]+).*~\\1~' output/allJSUrls_#{file_sanitized} | grep -v \"^*\\.\" | sed '/^\\s*$/d' | grep '\\.' | sort | uniq > output/tmp_scope.txt"
	system "xnLinkFinder -i output/allJSUrls_#{file_sanitized} -sf output/tmp_scope.txt -d 10 -sp #{file} -o output/xnLinkFinder_#{file_sanitized}"
	adding_anew("output/xnLinkFinder_#{file_sanitized}", "output/_tmpAllUrls_#{file_sanitized}")
	remove_using_scope(file, "output/_tmpAllUrls_#{file_sanitized}")
	
	# Find new URLS from Github using github-endpoints.py
	puts "\n[\e[36m+\e[0m] Finding more endpoints with github-endpoints.py"
	File.open("output/tmp_scope.txt",'r').each_line do |f|
		target = f.strip
		system "python ~/Tools/web-attack/github-search/github-endpoints.py -d #{target} -t #{$config['github_token']} | tee output/github-endpoints_#{file_sanitized}"
		adding_anew("output/github-endpoints_#{file_sanitized}", "output/_tmpAllUrls_#{file_sanitized}")
	end
	File.delete("output/tmp_scope.txt") if File.exists?("output/tmp_scope.txt")

	# Final
	remove_using_scope(file, "output/_tmpAllUrls_#{file_sanitized}")
	urless_fun("output/_tmpAllUrls_#{file_sanitized}", "output/allUrls_#{file_sanitized}")
	file_sanitization "output/allUrls_#{file_sanitized}"
	File.delete("parameters.txt") if File.exists?("parameters.txt")
	puts "[\e[36m+\e[0m] Results for #{file} saved as output/allUrls_#{file_sanitized}"

	# === SEARCH FOR VULNS ===
	if params[:vl_opt] == "y"
		params[:file] = "output/allUrls_#{file_sanitized}"
		params[:gb_opt] = "n" if params[:gb_opt] != "y"
		search_for_vulns params
	end

end



def find_vulns_fun(params)
	search_for_vulns params
end



def do_everything_fun(params)
	assetenum_fun params
	params[:file] = "output/http_#{params[:file].gsub("/", "")}"
	crawl_local_fun params
end



# ===================================
# ======= START OF THE SCRIPT =======
# ===================================

# Define a hash to map options to actions and descriptions
option_actions = {
	"firefox" => {
		action: ->(params) { firefox_fun(params) },
		description: "Open every entry in <file_input> with Firefox"
	},
	"get-to-burp" => {
		action: ->(params) { get_to_burp_fun(params) },
		description: "For every entry in <file_input>, send a GET request"
	},
	"assetenum" => {
		action: ->(params) { assetenum_fun(params) },
		description: "Asset enumeration, search also for some vulnerabilites with nuclei and 40* bypasses"
	},
	"webscreenshot" => {
		action: ->(params) { webscreenshot_fun(params) },
		description: "Take a screenshot for every entry in <file_input> and make a gallery"
	},
	"crawl-burp" => {
		action: ->(params) { crawl_burp_fun(params) },
		description: "Crawl for every entry in <file_input> and pass the results to Burp Suite"
	},
	"crawl-local" => {
		action: ->(params) { crawl_local_fun(params) },
		description: "Crawl for every entry in <file_input> and save the results in local. Optionally, scan for vulnerabilities"
	},
	"find-vulns" => {
		action: ->(params) { find_vulns_fun(params) },
		description: "Given a <file_input> containing URLs, scan for vunlerabilities (API Keys, Secrets, BLH, XSS, LFI)"
	},
	"do-everything" => {
		action: ->(params) { do_everything_fun(params) },
		description: "Asset enumeration > Crawl Locally > Scan for vunlerabilities"
	},
	"help" => {
		action: ->(options_actions) { show_help(option_actions) },
		description: "Show this text"
	}
}

begin
	puts logo

	# :: Pick an option ::

	valid_options = option_actions.keys.join(", ")

	print "\e[93m┌─\e[0m Enter an option [#{valid_options}]:\n\e[93m└─\e[0m "
	option = gets.chomp

	puts "\n"


	option_params = {}

	if option_actions.key?(option)

		params = {}

		options_that_need_file = ["firefox", "get-to-burp", "assetenum", "webscreenshot", "crawl-burp", "crawl-local", "find-vulns", "do-everything"]
		if options_that_need_file.include?(option)
			print "\e[93m┌─\e[0m Enter the file target:\n\e[93m└─\e[0m "
			params[:file] = gets.chomp
			puts "\n" if option == "firefox" || option == "get-to-burp" || option == "webscreenshot" || option == "crawl-burp"
		end

		if option == "assetenum" || option == "do-everything" || option == "crawl-local"
			print "\n\e[93m┌─\e[0m Search also for possible vulnerabilities? [y/n]:\n\e[93m└─\e[0m "
			params[:vl_opt] = gets.chomp
			puts "\n" if option == "crawl-local"
		end

		if option == "assetenum" || option == "do-everything" || option == "find-vulns"
			print "\n\e[93m┌─\e[0m Heavy mode? [y/n]:\n\e[93m└─\e[0m "
			params[:gb_opt] = gets.chomp
			puts "\n"
		end

		option_params[option] = params

		option_actions[option][:action].call(option_params[option])

	else
		puts "[\e[31m+\e[0m] Invalid option selected"
	end

rescue Interrupt
	puts "\n[\e[31m+\e[0m] Script interrupted by user. Exiting..."
	exit
end
