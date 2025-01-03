#!/usr/bin/env ruby

require 'uri'
require 'net/http'
require 'json'
require 'socket'
require 'yaml'
require 'thread'
require 'set'
require 'webdrivers'
require 'selenium-webdriver'

$CONFIG = YAML.load_file('config.yaml')



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



# :: Functions to make life easier ::



def adding_anew(file_tmp, file_final)
	if File.exists?(file_tmp)
		system "cat #{file_tmp} | anew #{file_final}"
		File.delete(file_tmp) if File.exists?(file_tmp)
	end
end



def delete_if_empty(file)
	if !File.exists?(file) || File.zero?(file)
		puts "[\e[36m+\e[0m] No result found"
		File.delete(file) if File.exists?(file)
	else
		puts "[\e[32m+\e[0m] Results added at #{file}"
	end
end



# :: Functions misc ::



def request_fun(uri)

	proxy_host = $CONFIG['proxy_addr']
	proxy_port = $CONFIG['proxy_port']

	headers = {
		"User-Agent" => $CONFIG['user-agent'],
		"Cookie" => $CONFIG['cookie'],
		"Authorization" => $CONFIG['authorization']
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



def extract_main_domains(input_file, output_file)
	domains = Set.new
	
	def extract_main_domain(url)
		begin
			uri = URI.parse(url)
			host = uri.host&.downcase
			return nil if host.nil? || host.empty?

			parts = host.split('.')

			return host if parts.length == 1 || host.match?(/\A\d{1,3}(\.\d{1,3}){3}\z/)

			if parts[-2].match?(/^(co|com|org|net|gov|edu|ac)$/) && parts.length > 2
				return "#{parts[-3]}.#{parts[-2]}.#{parts[-1]}"
			else
				return "#{parts[-2]}.#{parts[-1]}"
			end
		rescue URI::InvalidURIError
			nil
		end
	end

	File.open(input_file, 'r').each_line do |line|
		line.strip!
		next if line.empty?

		domain = extract_main_domain(line)
		domains.add(domain) unless domain.nil?
	end

	File.open(output_file, 'w') do |file|
		domains.each { |domain| file.puts(domain) }
	end
end



def send_telegram_notif(message)

	return unless $CONFIG['telegram'] && $CONFIG['telegram'] != "YOUR_TELEGRAM_TOKEN_HERE" && $CONFIG['telegram_chat_id'] && $CONFIG['telegram_chat_id'] != "YOUR_TELEGRAM_CHAT_ID_HERE"

	uri = URI.parse("https://api.telegram.org/bot#{$CONFIG['telegram']}/sendMessage")
	header = {'Content-Type': 'application/json'}
	body = {
		chat_id: $CONFIG['telegram_chat_id'],
		text: message
	}.to_json

	http = Net::HTTP.new(uri.host, uri.port)
	http.use_ssl = true
	request = Net::HTTP::Post.new(uri.request_uri, header)
	request.body = body

	retries = 3
	begin
		response = http.request(request)
		if response.code.to_i == 200
			puts "[\e[32m+\e[0m] Notification sent successfully with response: [\e[32m#{response.code} #{response.message}\e[0m]"
		else
			puts "[\e[31m+\e[0m] Failed to send notification. Response: [\e[31m#{response.code} #{response.message}\e[0m]"
		end
	rescue Net::OpenTimeout, Net::ReadTimeout => e
		puts "[\e[31m+\e[0m] Network timeout error: #{e.message}"
		if retries > 0
			retries -= 1
			puts "[\e[31m+\e[0m] Retrying... (#{3 - retries} attempts left)"
			sleep(1)
			retry
		end
	rescue SocketError => e
		puts "[\e[31m+\e[0m] Socket error: #{e.message}"
	rescue StandardError => e
		puts "[\e[31m+\e[0m] An unexpected error occurred: #{e.message}"
	end
end



# :: Functions to check URLs ::

def check_url(url, retries = 3)
	uri = URI.parse(url)
	response = nil

	begin
		# Set up HTTP object with timeouts
		http = Net::HTTP.new(uri.host, uri.port)
		http.open_timeout = 5	# seconds for opening the connection
		http.read_timeout = 10  # seconds for reading the response

		if uri.scheme == 'https'
			http.use_ssl = true
			http.verify_mode = OpenSSL::SSL::VERIFY_NONE
		end

		request = Net::HTTP::Get.new(uri.request_uri)

		# Perform the request
		response = http.request(request)

	rescue Timeout::Error, Errno::ETIMEDOUT, Net::OpenTimeout => e
		retries -= 1
		if retries > 0
			puts "[\e[33m*\e[0m] Timeout on URL: #{url}. Retrying... (#{retries} retries left)"
			sleep(1)
			retry
		else
			puts "[\e[31m-\e[0m] Timeout on URL: #{url}. Skipping after retries."
			return nil
		end
	rescue SocketError, Errno::ECONNREFUSED => e
		puts "[\e[31m-\e[0m] Connection error on URL: #{url}. Skipping."
		return nil
	rescue => e
		puts "[\e[31m!\e[0m] Error checking URL #{url}: #{e.message}"
		return nil
	end

	response
end



# Get a file containing URLs, check for their status code with check_url
# If the status code is the one desired, creates a new file containing the results
def process_urls_for_code(file_to_scan, output_file, status_code, num_threads = $CONFIG['n_threads'])
	queue = Queue.new

	# Load all URLs into the queue
	File.foreach(file_to_scan) do |url|
		url.strip!
		queue << url unless url.empty?
	end

	File.open(output_file, 'w') do |output|
		mutex = Mutex.new

		workers = Array.new(num_threads) do
			Thread.new do
				while !queue.empty? && url = queue.pop(true) rescue nil
					response = check_url(url)
					if response && response.code.to_i == status_code
						mutex.synchronize do
							output.puts(url)
							puts url
						end
					end
				end
			end
		end

		workers.each(&:join)
	end

rescue Exception => e
	puts "[\e[31m!\e[0m] ERROR: #{e.message}"

end



def contains_only_tracking_params?(url)
	uri = URI.parse(url)
	return false if uri.query.nil? || uri.query.empty? # check if there are parameters, if not return false

	tracking_params = %w[utm_source utm_medium utm_campaign utm_term utm_content gclid gad_source fbclid __cf_chl_rt_tk]
	params = URI.decode_www_form(uri.query).map(&:first)

	(params - tracking_params).empty?
rescue
	false
end



# :: Functions to clean files ::



def remove_ansi(file_path)
	unless File.exists?(file_path)
		puts "[\e[31m+\e[0m] File not found: #{file_path}"
		return
	end

	sed_command = "sed -r -i -e 's/\\x1B\\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g' #{file_path}"

	unless system(sed_command)
		puts "[\e[31m!\e[0m] Error processing file"
	end
end



def file_sanitization(file_path)
	unless File.exists?(file_path)
		puts "[\e[31m+\e[0m] File not found: #{file_path}"
		return
	end

	sanitized_lines = []

	def sanitize_url(url)
		uri = URI.parse(url)
	
		def encode_component(component)
			component.gsub(/%[0-9A-Fa-f]{2}/) { |match| match }.split(/(%[0-9A-Fa-f]{2})/).map { |segment| segment.match?(/%[0-9A-Fa-f]{2}/) ? segment : URI.encode_www_form_component(segment).gsub('%', '%25') }.join
		end

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



def remove_using_scope(scope_file, url_file)
	scope_urls = File.readlines(scope_file).map(&:strip)
	urls = File.readlines(url_file).map(&:strip)
	
	scope_hosts = scope_urls.map do |url|
		begin
			URI(url).host
		rescue => e
			puts "[\e[31m!\e[0m] ERROR: #{e.message}"
		end
	end

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
rescue => e
	puts "[\e[31m!\e[0m] ERROR: #{e.message}"
end



def clean_urls(file_path, num_threads = $CONFIG['n_threads'])
	puts "[\e[34m*\e[0m] Starting URL cleaning process..."

	# Step 1: Clean file
	puts "[\e[34m*\e[0m] Cleaning file..."
	file_sanitization file_path

	# Step 2: Filter only valid URLs using sed
	puts "[\e[34m*\e[0m] Filtering valid URLs..."
	system "sed -i -E '/^(http|https):/!d' #{file_path}"

	# Step 3: Process the file with urless to deduplicate URLs
	puts "[\e[34m*\e[0m] Running urless to deduplicate URLs..."
	urless_command = "urless -i #{file_path} -o #{file_path}.tmp"
	if system(urless_command)
		File.rename("#{file_path}.tmp", file_path)
		puts "[\e[32m+\e[0m] Urless processing complete, deduplicated URLs written to #{file_path}"
	else
		puts "[\e[31m!\e[0m] Error running urless"
		return
	end

	# Step 4: Remove useless URLs like _Incapsula_Resource
	puts "[\e[34m*\e[0m] Removing useless URLs..."
	urls = File.readlines(file_path).map(&:strip).reject(&:empty?)
	filtered_urls = urls.reject { |url| url.include?('_Incapsula_Resource') }
	puts "[\e[32m+\e[0m] Useless URLs removed"

	# Step 5: Remove URLs with only tracking parameters
	puts "[\e[34m*\e[0m] Removing URLs with only tracking parameters..."
	filtered_urls.reject! { |url| contains_only_tracking_params?(url) }
	puts "[\e[32m+\e[0m] URLs with only tracking parameters removed"

	# Step 6: Remove dead links and 404 URLs
	puts "[\e[34m*\e[0m] Checking for dead links and 404 URLs..."
	queue = Queue.new
	filtered_urls.each { |url| queue << url }

	live_urls = []
	mutex = Mutex.new

	workers = Array.new(num_threads) do
		Thread.new do
			until queue.empty?
				url = queue.pop(true) rescue nil
				next unless url

				response = check_url(url)
				if response && response.is_a?(Net::HTTPSuccess)
					mutex.synchronize { live_urls << url }
					puts "[\e[32m+\e[0m] Alive URL: #{url}"
				elsif response && response.code.to_i == 404
					puts "[\e[31m+\e[0m] 404 Not Found: #{url}"
				else
					puts "[\e[31m+\e[0m] Dead URL: #{url}"
				end
			end
		end
	end

	workers.each(&:join)

	# Step 7: Overwrite the input file with the cleaned URLs
	puts "[\e[34m*\e[0m] Writing cleaned URLs to file..."
	File.open(file_path, 'w') { |file| file.puts(live_urls) }
	puts "[\e[32m+\e[0m] Cleaned URLs written to #{file_path}"

end




# :: Functions to identify technologies ::



def is_wordpress?(response)
	return false unless response.is_a?(Net::HTTPSuccess)
	body = response.body

	wordpress_regexes = [
		%r{<generator>https?:\/\/wordpress\.org.*</generator>},
		%r{wp-login.php},
		%r{\/wp-content/themes\/},
		%r{\/wp-includes\/},
		%r{name="generator" content="wordpress},
		%r{<link[^>]+s\d+\.wp\.com},
		%r{<!-- This site is optimized with the Yoast (?:WordPress )?SEO plugin v([\d.]+) -},
		%r{<!--[^>]+WP-Super-Cache}
	]

	wordpress_regexes.any? { |regex| body.match?(regex) }
end



def is_drupal?(response)
	return false unless response.is_a?(Net::HTTPSuccess)
	body = response.body

	drupal_regexes = [
		%r{<meta name="Generator" content="Drupal.*?>},
		%r{\/sites\/all\/},
		%r{\/misc\/drupal.js},
		%r{X-Generator: Drupal}
	]

	drupal_regexes.any? { |regex| body.match?(regex) } ||
		response['X-Generator']&.include?('Drupal')
end



def is_salesforce?(response)
	return false unless response.is_a?(Net::HTTPSuccess)
	body = response.body

	salesforce_regexes = [
		%r{\.force\.com},
		%r{\.salesforce\.com},
		%r{\/auraFW\/},
		%r{\/s\/}
	]

	salesforce_regexes.any? { |regex| body.match?(regex) } ||
		response['X-Salesforce-Cache']
end



def is_lotus_domino?(response)
	return false unless response.is_a?(Net::HTTPSuccess)
	body = response.body

	lotus_domino_regexes = [
	  %r{Domino\s[A-Za-z]+\s[0-9\.]{1,3}},
	  %r{Forms[0-9\.]{1,3}\.nsf\?OpenDatabase}
	]

	lotus_domino_regexes.any? { |regex| body.match?(regex) }
end


def is_iis?(response)
	return false unless response.is_a?(Net::HTTPSuccess)
	body = response.body

	iis_headers = [
		/Microsoft-IIS\/[\d.]+/,
		/ASP\.NET/
	]

	iis_body_regexes = [
		%r{<title>IIS Windows Server</title>},
		%r{<h1>Welcome</h1>\s*<h2>IIS}
	]

	iis_headers.any? { |regex| response['Server']&.match?(regex) || response['X-Powered-By']&.match?(regex) } ||
		iis_body_regexes.any? { |regex| body.match?(regex) }
end



def identify_technology(file_to_scan, num_threads = $CONFIG['n_threads'])
	queue = Queue.new
	technologies = { wp: [], drupal: [], salesforce: [], lotus_domino: [], iis: [] }

	File.foreach(file_to_scan) do |url|
		url.strip!
		queue << url unless url.empty?
	end

	mutex = Mutex.new

	workers = Array.new(num_threads) do
		Thread.new do
			while !queue.empty? && (url = queue.pop(true) rescue nil)
				next unless url
				response = check_url(url)

				if response
					if is_wordpress?(response)
						mutex.synchronize { technologies[:wp] << url }
					elsif is_drupal?(response)
						mutex.synchronize { technologies[:drupal] << url }
					elsif is_salesforce?(response)
						mutex.synchronize { technologies[:salesforce] << url }
					elsif is_lotus_domino?(response)
						mutex.synchronize { technologies[:lotus_domino] << url }
					elsif is_iis?(response)
						mutex.synchronize { technologies[:iis] << url }
					end
				end
			end
		end
	end

	workers.each(&:join)

	technologies
end



# :: Functions to search for vulnerabilities ::



def check_file_upload(body)
	if body.match(/<input[^>]+type=['"]file['"][^>]*>/i)
		return true
	end
	false
rescue => e
	puts "[!] Error in check_file_upload: #{e.message}"
	nil
end



# search_for_vulns but for base URLs
def base_url_s4v(file)

	system "mkdir output" if !File.directory?('output')

	file_sanitized = file.gsub("/", "")

	# Use some Nuclei templates
	puts "\n[\e[34m*\e[0m] Searching for subdomain takeovers and exposed panels with nuclei in #{file}"
	system "nuclei -l #{file} -tags takeover,panel -stats -o output/nuclei_#{file_sanitized}"
	delete_if_empty "output/nuclei_#{file_sanitized}"

	# Search for 401 and 403 bypasses
	puts "\n[\e[34m*\e[0m] Searching for 401,403 and bypasses in #{file}"
	process_urls_for_code("#{file}", "output/40X_#{file_sanitized}", 403)
	process_urls_for_code("#{file}", "output/401_#{file_sanitized}", 401)
	system "cat output/401_#{file_sanitized} >> output/40X_#{file_sanitized} && rm output/401_#{file_sanitized}" if File.exists?("output/401_#{file_sanitized}")
	system "byp4xx -xB -m 2 -L output/40X_#{file_sanitized} | grep -v '==' |tee output/byp4xx_results_#{file_sanitized}"
	system "dirsearch -e * -x 429,406,404,403,401,400 -l output/40X_#{file_sanitized} --no-color --full-url -t #{$CONFIG['n_threads']} -o output/dirsearch_results_40X_#{file_sanitized}"
	remove_ansi "output/byp4xx_results_#{file_sanitized}"
	system "rm -rf reports/" if File.directory?('reports')

	puts "\n[\e[36m+\e[0m] Searching for technologies and specific vulnerabilities in #{file}"
	tech_identified = identify_technology(file)

	# write all the techs identified
	File.open("output/#{file_sanitized}_tech_identified.txt", 'w') do |file|
		tech_identified.each do |tech, urls|
			next if urls.empty?

			file.puts "#{tech.to_s.capitalize} sites identified:"

			urls.each { |url| file.puts "	- #{url}" }

			file.puts ""
		end
	end
	puts "[\e[32m+\e[0m] Technologies identified have been saved to output/#{file_sanitized}_tech_identified.txt"
	
	# TODO:
	# - [ ] Aggiungere FavFreak > aggiungere a file_sanitized_tech_identified.txt con anew, `cat urls.txt | python3 favfreak.py -o output`

	# WordPress
	if tech_identified[:wp].any?
		system "mkdir output/wpscan" if !File.directory?('output/wpscan')
		tech_identified[:wp].each do |f|
			target = f.chomp
			sanitized_target = target.gsub(/[^\w\s]/, '_')[0, 255]
			puts "\n[\e[34m*\e[0m] Starting WPScan for #{target}"
			if !$CONFIG['wpscan'].nil? || $CONFIG['wpscan'] != "YOUR_WPSCAN_TOKEN_HERE"
				system "wpscan --url #{target} --api-token #{$CONFIG['wpscan']} -t #{$CONFIG['n_threads']} --plugins-detection mixed -e vp,vt,cb,dbe,u1-10 --force -f cli-no-color --exclude-content-based --random-user-agent -o output/wpscan/wpscan_#{sanitized_target}_#{file_sanitized}"
			else
				system "wpscan --url #{target} -t #{$CONFIG['n_threads']} --plugins-detection mixed -e vp,vt,cb,dbe,u1-10 --force -f cli-no-color --exclude-content-based --random-user-agent -o output/wpscan/wpscan_#{sanitized_target}_#{file_sanitized}"
			end
		end
	end

	# Drupal
	if tech_identified[:drupal].any?
		system "mkdir output/droopescan" if !File.directory?('output/droopescan')
		tech_identified[:drupal].each do |f|
			target = f.chomp
			sanitized_target = target.gsub(/[^\w\s]/, '_')[0, 255]
			system "droopescan scan drupal -u #{target} -t #{$CONFIG['n_threads']} | tee output/droopescan/droopescan_#{sanitized_target}.txt"
		end
	end

	# Salesforce
	if tech_identified[:salesforce].any?
		system "mkdir output/salsa" if !File.directory?('output/salsa')
		tech_identified[:salesforce].each do |f|
			target = f.chomp
			sanitized_target = target.gsub(/[^\w\s]/, '_')[0, 255]
			system "java -jar ~/Tools/web-attack/SALSA/salsa-jar-with-dependencies.jar -t #{target} --typesapi | tee output/salsa/salsa_#{sanitized_target}.txt"
		end
	end

	# Lotus
	if tech_identified[:lotus_domino].any?
		system "mkdir output/lotus" if !File.directory?('output/lotus')
		tech_identified[:lotus_domino].each do |f|
			target = f.chomp
			sanitized_target = target.gsub(/[^\w\s]/, '_')[0, 255]
			system "dirsearch -e * -x 429,406,404,403,401,400 -u #{target} --no-color --full-url -t #{$CONFIG['n_threads']} -w '~/Tools/SecLists/Discovery/Web-Content/LotusNotes.fuzz.txt' -o output/lotus/dirsearch_results_#{sanitized_target}"
		end
	end

	if tech_identified[:iis].any?
		system "mkdir output/iis" if !File.directory?('output/iis')
		tech_identified[:iis].each do |f|
			target = f.chomp
			sanitized_target = target.gsub(/[^\w\s]/, '_')[0, 255]
			system "shortscan #{target} --verbosity 1 | tee output/iis/iis_results_#{sanitized_target}"
		end
	end

	send_telegram_notif("Search for vulns for #{file} finished")
end



def search_for_vulns(params, num_threads = $CONFIG['n_threads'])

	file_to_scan = params[:file]

	system "mkdir output" if !File.directory?('output')

	o_sanitized = file_to_scan.gsub(/[^\w\s]/, '_')

	# Get only 200s
	process_urls_for_code(file_to_scan, "output/200_#{o_sanitized}.txt", 200)

	# :: Mantra ::
	puts "\n[\e[34m*\e[0m] Searching for secrets with Mantra"
	system "cat output/200_#{o_sanitized}.txt | grep -v \"\\.pdf\" | mantra -t #{$CONFIG['n_threads']} | grep \"\\[+\\]\" | tee output/mantra_results_#{o_sanitized}.txt"
	delete_if_empty "output/mantra_results_#{o_sanitized}.txt"
	remove_ansi "output/mantra_results_#{o_sanitized}.txt"

	## :: Grep only params ::
	system "cat #{file_to_scan} | grep -Evi '\\.(js|jsx|svg|png|pngx|gif|gifx|ico|jpg|jpgx|jpeg|jfif|jpg-large|bmp|mp3|mp4|ttf|woff|ttf2|woff2|eot|eot2|swf2|css|pdf|webp|tif|xlsx|xls|map)' | grep \"?\" | tee output/allParams_#{o_sanitized}.txt"
	
	report_file_path = "output/file_uploads_#{o_sanitized}.txt"
	File.open(report_file_path, 'w') do |report_file|
		workers = Array.new(num_threads) do
			Thread.new do
				while !queue.empty?
					url = queue.pop(true) rescue nil
					next unless url

					response = check_url(url)
					next unless response

					content_type = response['content-type']
					if content_type && content_type.include?('text/html')
						body = response.body
						found = check_file_upload(body)

						message = found ? "[+] File upload found on #{url}" : "[-] No file upload found on #{url}"
						puts message

						if found
							mutex.synchronize do
								report_file.puts(url)
							end
						end
					end
				end
			end
		end

		workers.each(&:join)
	end

	# TODO:
	#	- [x] Check for file uploads
	#	- [ ] Check for reflections

	send_telegram_notif("Search for vulnerabilities for #{file_to_scan} finished")

rescue Exception => e
	puts "[!] ERROR in search_for_vulns: #{e.message}"
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



def get_to_burp_fun(params, num_threads = $CONFIG['n_threads'])
	queue = Queue.new
	mutex = Mutex.new

	File.foreach(params[:file]) do |line|
		url = line.strip
		queue << url unless url.empty?
	end

	workers = Array.new(num_threads) do
		Thread.new do
			while !queue.empty? && f = queue.pop(true) rescue nil

				begin
					redirect = 3
					base_uri = URI.parse(f)

					res = request_fun(base_uri)

					mutex.synchronize do
						puts "[\e[36m+\e[0m] GET > #{f}"
					end

					while res.is_a?(Net::HTTPRedirection) && redirect > 0
						location = res['location'].to_s
						mutex.synchronize do
							puts "		Redirecting to > #{location}"
						end

						uri = URI.parse(location)
						uri = base_uri + uri if uri.relative?

						res = request_fun(uri)
						redirect -= 1
					end

				rescue Net::OpenTimeout, Net::ReadTimeout => e
					mutex.synchronize do
						puts "[\e[31m-\e[0m] TIMEOUT ERROR: #{e.message}"
					end
				rescue StandardError => e
					mutex.synchronize do
						puts "[\e[31m!\e[0m] ERROR: #{e.message}"
					end
				end
			end
		end
	end

	workers.each(&:join)
end



def assetenum_fun(params)

	file = params[:file]

	system "mkdir output" if !File.directory?('output')

	File.open(file,'r').each_line do |f|

		target = f.chomp

		#== amass ==

		if params[:gb_opt] == "y"
			puts "\n[\e[34m*\e[0m] Enumerating subdomains for #{target} with amass"
			system "amass enum -brute -active -d #{target} -v -dns-qps 300"
			system "oam_subs -names -d #{target} | tee output/#{target}_tmp.txt"
		else
			puts "\n[\e[34m*\e[0m] Enumerating subdomains for #{target} with amass"
			system "amass enum -passive -d #{target} -v -timeout 15 -dns-qps 300"
			system "oam_subs -names -d #{target} | tee output/#{target}_tmp.txt"
		end

		#== subfinder ==
		puts "\n[\e[34m*\e[0m] Enumerating subdomains for #{target} with subfinder"
		system "subfinder -d #{target} -all -o output/#{target}_subfinder.txt"

		adding_anew("output/#{target}_subfinder.txt", "output/#{target}_tmp.txt")

		#== github-subdomains ==
		if !$CONFIG['github_token'].nil? || $CONFIG['github_token'] != "YOUR_GITHUB_TOKEN_HERE"
			puts "\n[\e[34m*\e[0m] Enumerating subdomains for #{target} with github-subdomains"
			system "github-subdomains -t #{$CONFIG['github_token']} -d #{target} -o output/#{target}_github.txt"
			adding_anew("output/#{target}_github.txt", "output/#{target}_tmp.txt")
		end

		#== crt.sh ==
		puts "\n[\e[34m*\e[0m] Enumerating subdomains for #{target} with crt.sh"

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
			puts "[\e[31m!\e[0m] ERROR: #{e.message}"
		end

		#== gobuster ==

		if params[:gb_opt] == "y"

			if !File.exists?("all.txt")
				uri = URI.parse("https://gist.githubusercontent.com/jhaddix/86a06c5dc309d08580a018c66354a056/raw/96f4e51d96b2203f19f6381c8c545b278eaa0837/all.txt")
				response = Net::HTTP.get_response(uri)
				alltxt = (response.body).to_s
				File.open('all.txt', 'w') { |file| file.write(alltxt) }
			end

			puts "\n[\e[34m*\e[0m] Enumerating subdomains for #{target} with gobuster and all.txt"
			system "gobuster dns -d #{target} -v -t #{$CONFIG['n_threads']} --no-color --wildcard -o output/#{target}_gobuster_tmp.txt -w all.txt"

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

		#system "amass enum -nf output/#{target}_tmp.txt -d #{target}"

		#== anew final ==

		puts "\n[\e[34m*\e[0m] Checking if IPs for the subdomains of #{target} exist"

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

		puts "[\e[32m+\e[0m] Results for #{target} saved as output/#{target}.txt"

		puts "\n[\e[34m*\e[0m] Adding the results for #{target} to output/allsubs_#{file}"
		adding_anew("output/#{target}.txt","output/allsubs_#{file}")
		puts "[\e[32m+\e[0m] Results for #{file} saved as output/allsubs_#{file}"

	end

	#== httpx & httprobe ==
	puts "\n[\e[34m*\e[0m] Searching for web services output/allsubs_#{file}"
	system "cat output/allsubs_#{file} | httpx-toolkit -t #{$CONFIG['n_threads']} -p 80,81,82,88,135,143,300,443,554,591,593,832,902,981,993,1010,1024,1099,1311,2077,2079,2082,2083,2086,2087,2095,2096,2222,2480,3000,3001,3002,3003,3128,3306,3333,3389,4243,4443,4567,4711,4712,4993,5000,5001,5060,5104,5108,5280,5281,5357,5432,5601,5800,5985,6379,6543,7000,7001,7170,7396,7474,7547,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8085,8088,8089,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9092,9100,9200,9443,9502,9800,9981,9999,10000,10250,10443,11371,12345,12443,15672,16080,17778,18091,18092,20720,28017,32000,49152,55440,55672 -o output/http_#{file}"
	system "cat output/allsubs_#{file} | httprobe -p http:81 -p http:3000 -p https:3000 -p http:3001 -p https:3001 -p http:8000 -p http:8080 -p https:8443 -c 100 | anew output/http_#{file}"
	puts "[\e[32m+\e[0m] Results saved as output/http_#{file}"

	#== naabu ==
	if params[:gb_opt] == "y"
		puts "\n[\e[34m*\e[0m] Searching for more open ports in output/allsubs_#{file} with naabu"
		system "naabu -v -list output/allsubs_#{file} -p - -exclude-ports 80,81,82,88,135,143,300,443,554,591,593,832,902,981,993,1010,1024,1099,1311,2077,2079,2082,2083,2086,2087,2095,2096,2222,2480,3000,3001,3002,3003,3128,3306,3333,3389,4243,4443,4567,4711,4712,4993,5000,5001,5060,5104,5108,5280,5281,5357,5432,5601,5800,5985,6379,6543,7000,7001,7170,7396,7474,7547,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8085,8088,8089,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9092,9100,9200,9443,9502,9800,9981,9999,10000,10250,10443,11371,12345,12443,15672,16080,17778,18091,18092,20720,28017,32000,49152,55440,55672 -c 1000 -rate 7000 -stats -o output/ports_#{file}"
		delete_if_empty "output/ports_#{file}"
	end

	#== naabu | httpx & httprobe ==
	if File.exists?("output/ports_#{file}")
		puts "\n[\e[34m*\e[0m] Searching for hidden web ports in output/ports_#{file}"
		system "cat output/ports_#{file} | httpx-toolkit -t #{$CONFIG['n_threads']} -o output/http_hidden_#{file}"
		system "cat output/ports_#{file} | httprobe | anew output/http_hidden_#{file}"

		if File.exists?("output/http_hidden_#{file}")
			system "cat output/http_hidden_#{file}"
			adding_anew("output/http_hidden_#{file}", "output/http_#{file}")
			puts "[\e[32m+\e[0m] Results added to output/http_#{file}"
		end
	end

	# == Interesting subs ==

	puts "\n[\e[34m*\e[0m] Showing some interesting subdomains found"
	system "cat output/allsubs_#{file} | grep -E \"jenkins|jira|gitlab|github|sonar|bitbucket|travis|circleci|eslint|pylint|junit|testng|pytest|jest|selenium|appium|postman|newman|cypress|seleniumgrid|artifactory|nexus|ansible|puppet|chef|deploybot|octopus|prometheus|grafana|elk|slack|admin|geoservice|teams\" | sort -u | tee output/interesting_subdomains_#{file}"
	system "cat output/http_#{file} | grep -E \"jenkins|jira|gitlab|github|sonar|bitbucket|travis|circleci|eslint|pylint|junit|testng|pytest|jest|selenium|appium|postman|newman|cypress|seleniumgrid|artifactory|nexus|ansible|puppet|chef|deploybot|octopus|prometheus|grafana|elk|slack|admin|geoservice|teams\" | sort -u | anew output/interesting_subdomains_#{file}"
	delete_if_empty "output/interesting_subdomains_#{file}"

	send_telegram_notif("Asset enumeration for #{file} finished")

	# == Search for vulns ==
	if params[:vl_opt] == "y"
		base_url_s4v "output/http_#{file}"
	end

end



def webscreenshot_fun(params, num_threads = $CONFIG['n_threads'])
	urls = File.readlines(params[:file]).map(&:chomp)

	i = 0
	image_paths = []
	successful_urls = []
	queue = Queue.new

	urls.each { |url| queue << url }

	system "mkdir output" if !File.directory?('output')
	system "mkdir output/webscreen" if !File.directory?('output/webscreen')

	options = Selenium::WebDriver::Chrome::Options.new
	options.add_argument('--ignore-certificate-errors')
	options.add_argument('--disable-popup-blocking')
	options.add_argument('--disable-translate')
	options.add_argument('--ignore-certificate-errors-spki-list')
	options.add_argument('--window-size=2560,1440')
	options.add_argument('--headless')

	mutex = Mutex.new
	workers = []

	num_threads.times do
		workers << Thread.new do
			driver = Selenium::WebDriver.for :chrome, options: options

			while !queue.empty? && url = queue.pop(true) rescue nil
				begin
					driver.navigate.to url

					image_path = "output/webscreen/#{url.gsub(/[^\w\s]/, '_')}.png"
					driver.save_screenshot(image_path)

					mutex.synchronize do
						i += 1
						puts "[\e[32m#{i}\e[0m] Screenshot saved as: #{image_path}"
						image_paths << image_path
						successful_urls << url
					end
				rescue Exception => e
					mutex.synchronize do
						puts "[\e[31m#{i}\e[0m] ERROR while trying to take a screenshot of #{url}: #{e.message}"
					end
				end
			end

			driver.quit
		end
	end

	workers.each(&:join)

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
			html.write("<img src=\"#{path.gsub('output/', '')}\" alt=\"Screenshot #{successful_urls[index]}\" width=\"600\" height=\"400\">")
			html.write("</a>")
			html.write("<div class=\"screenshot-desc\"><b>URL:</b> <a href=\"#{successful_urls[index]}\" target=_blank>#{successful_urls[index]}</a></div>")
			html.write('</div>')
		end

		html.write('</body>')
		html.write('</html>')
	end
end



def crawl_local_fun(params)

	file = params[:file]
	file_sanitized = file.gsub("/", "")
	target_tmp = ""

	system "mkdir output" if !File.directory?('output')

	File.open(file,'r').each_line do |f|
		target = f.chomp
		target_sanitized = target.gsub(/^https?:\/\//, '').gsub(/:\d+$/, '').gsub('/','')

		puts "\n[\e[34m*\e[0m] Crawling #{target} with katana\n"
		system "katana -u #{target} -jc -jsl -hl -kf -aff -d 3 -p 25 -c 25 -fs fqdn -H \"Cookie: #{$CONFIG['cookie']}\" -o output/#{target_sanitized}_tmp.txt"

		puts "\n[\e[34m*\e[0m] Crawling #{target} with gau\n"
		system "echo #{target}| gau --blacklist svg,png,gif,ico,jpg,jpeg,jfif,jpg-large,bpm,mp3,mp4,ttf,woff,ttf2,woff2,eot,eot2,swf,swf2,css --fc 404 --threads #{$CONFIG['n_threads']} --verbose --o output/#{target_sanitized}_gau.txt"
		adding_anew("output/#{target_sanitized}_gau.txt", "output/#{target_sanitized}_tmp.txt")

		if target_sanitized != target_tmp
			puts "\n[\e[34m*\e[0m] Finding more endpoints for #{target_sanitized} with ParamSpider\n"
			system "paramspider -d #{target_sanitized}"
		end
		target_tmp = target_sanitized
		adding_anew("results/#{target_sanitized}.txt", "output/#{target_sanitized}_tmp.txt")
		
		puts ""
		clean_urls "output/#{target_sanitized}_tmp.txt"
		adding_anew("output/#{target_sanitized}_tmp.txt","output/allUrls_#{file_sanitized}")
		puts "[\e[32m+\e[0m] Results for #{target} saved in output/allUrls_#{file_sanitized}"
	end

	# waymore
	
	extract_main_domains("output/allUrls_#{file_sanitized}", "output/_tmp_domains_#{file_sanitized}")
	File.open("output/_tmp_domains_#{file_sanitized}",'r').each_line do |f|
		target = f.strip
		puts "\n[\e[34m*\e[0m] Finding more endpoints for #{target} with WayMore\n"
		system "waymore -i #{target} -c /home/kali/.config/waymore/config.yml -f -p 5 -mode U -oU output/#{target}_waymore.txt"
		sleep(30)
		clean_urls "output/#{target}_waymore.txt"
		adding_anew("output/#{target}_waymore.txt","output/allUrls_#{file_sanitized}")
		sleep(30)
	end
	
	# Find new URLS from Github using github-endpoints.py
	if !$CONFIG['github_token'].nil? || $CONFIG['github_token'] != "YOUR_GITHUB_TOKEN_HERE"
		puts "\n[\e[34m*\e[0m] Finding more endpoints with github-endpoints.py"
		File.open("output/_tmp_domains_#{file_sanitized}",'r').each_line do |f|
			target = f.strip
			system "python ~/Tools/web-attack/github-search/github-endpoints.py -d #{target} -t #{$CONFIG['github_token']} | tee output/github-endpoints_#{file_sanitized}"
			clean_urls "output/github-endpoints_#{file_sanitized}"
			adding_anew("output/github-endpoints_#{file_sanitized}", "output/allUrls_#{file_sanitized}")
		end
	end

	# JS file analysis
	puts "\n[\e[34m*\e[0m] Searching for JS files"
	system "cat output/allUrls_#{file_sanitized} | grep '\\.js$' | tee output/_tmpAllJSUrls_#{file_sanitized}"
	system "cat output/allUrls_#{file_sanitized} | getJS -threads #{$CONFIG['n_threads']} -complete -resolve | anew output/_tmpAllJSUrls_#{file_sanitized}"
	clean_urls "output/_tmpAllJSUrls_#{file_sanitized}"
	system "cat output/_tmpAllJSUrls_#{file_sanitized} | anew output/allUrls_#{file_sanitized}"

	# Just keep it 200 for JS files
	process_urls_for_code("output/_tmpAllJSUrls_#{file_sanitized}", "output/allJSUrls_#{file_sanitized}", 200)
	File.delete("output/_tmpAllJSUrls_#{file_sanitized}") if File.exists?("output/_tmpAllJSUrls_#{file_sanitized}")
	puts "[\e[32m+\e[0m] Results saved as output/allJSUrls_#{file_sanitized}"

	# Find new URLs from the JS files
	puts "\n[\e[34m*\e[0m] Finding more endpoints from output/allJSUrls_#{file_sanitized} with xnLinkFinder"
	system "sed -E 's~^[a-zA-Z]+://([^:/]+).*~\\1~' output/allUrls_#{file_sanitized} | grep -v \"^*\\.\" | sed '/^\\s*$/d' | grep '\\.' | sort | uniq > output/tmp_scope.txt"
	system "xnLinkFinder -i output/allJSUrls_#{file_sanitized} -sf output/tmp_scope.txt -p #{$CONFIG['n_threads']} -vv -insecure -sp #{file} -o output/xnLinkFinder_#{file_sanitized}"
	clean_urls "output/xnLinkFinder_#{file_sanitized}"
	adding_anew("output/xnLinkFinder_#{file_sanitized}", "output/allUrls_#{file_sanitized}")
	File.delete("output/allJSUrls_#{file_sanitized}") if File.exists?("output/allJSUrls_#{file_sanitized}")

	# Final
	File.delete("output/_tmp_domains_#{file_sanitized}") if File.exists?("output/_tmp_domains_#{file_sanitized}")
	File.delete("output/tmp_scope.txt") if File.exists?("output/tmp_scope.txt")
	File.delete("parameters.txt") if File.exists?("parameters.txt")
	system "rm -rf results/"
	remove_using_scope(file, "output/allUrls_#{file_sanitized}")
	puts "[\e[32m+\e[0m] Results for #{file} saved as output/allUrls_#{file_sanitized}"
	send_telegram_notif("Crawl-local for #{file} finished")

	# === SEARCH FOR VULNS ===
	if params[:vl_opt] == "y"
		params[:file] = "output/allUrls_#{file_sanitized}"
		search_for_vulns params
	end

end



def find_vulns_fun(params)
	search_for_vulns params
end



def find_vulns_base_fun(params)
	base_url_s4v params[:file]
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
		description: "For every entry in <file_input>, send a GET request using Burp Suite as a proxy"
	},
	"assetenum" => {
		action: ->(params) { assetenum_fun(params) },
		description: "Asset enumeration, search also for some vulnerabilites"
	},
	"webscreenshot" => {
		action: ->(params) { webscreenshot_fun(params) },
		description: "Take a screenshot for every entry in <file_input> and make a gallery"
	},
	"crawl-local" => {
		action: ->(params) { crawl_local_fun(params) },
		description: "Crawl for every entry in <file_input> and save the results in local. Optionally, scan for vulnerabilities"
	},
	"find-vulns" => {
		action: ->(params) { find_vulns_fun(params) },
		description: "Given a <file_input> containing URLs, scan for vulnerabilities"
	},
	"find-vulns-base-url" => {
		action: ->(params) { find_vulns_base_fun(params) },
		description: "Given a <file_input> containing base URLs, scan for vulnerabilities"
	},
	"do-everything" => {
		action: ->(params) { do_everything_fun(params) },
		description: "Asset enumeration > Crawl Locally > Scan for vulnerabilities"
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

		options_that_need_file = ["firefox", "get-to-burp", "assetenum", "webscreenshot", "crawl-local", "find-vulns", "find-vulns-base-url", "do-everything"]
		if options_that_need_file.include?(option)
			print "\e[93m┌─\e[0m Enter the file target:\n\e[93m└─\e[0m "
			params[:file] = gets.chomp
			puts "\n" if option == "firefox" || option == "get-to-burp" || option == "webscreenshot"
		end

		if option == "assetenum" || option == "do-everything" || option == "crawl-local"
			print "\n\e[93m┌─\e[0m Search also for possible vulnerabilities? [y/n]:\n\e[93m└─\e[0m "
			params[:vl_opt] = gets.chomp
			puts "\n" if option == "crawl-local"
		end

		if option == "assetenum" || option == "do-everything"
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
rescue StandardError => e
	puts "\n[\e[31m+\e[0m] An error occurred: #{e.message}"
	puts e.backtrace
	send_telegram_notif 'easyg.rb crashed'
	exit 1
end
