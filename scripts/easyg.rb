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



# :: Functions misc ::



def adding_anew(file_tmp, file_final)
	return unless File.exist?(file_tmp)

	# Read existing lines from final file
	existing_lines = Set.new
	if File.exist?(file_final)
		File.foreach(file_final) { |line| existing_lines.add(line.chomp) }
	end

	# Find new lines in tmp file
	new_lines = []
	File.foreach(file_tmp) do |line|
		line.chomp!
		new_lines << line unless existing_lines.include?(line)
	end

	# Append new lines to final file
	if !new_lines.empty?
		File.open(file_final, 'a') do |f|
			new_lines.each { |line| f.puts(line) }
		end
	end

	File.delete(file_tmp)
end



def delete_if_empty(file)
	if !File.exists?(file) || File.zero?(file)
		puts "[\e[36m+\e[0m] No result found"
		File.delete(file) if File.exists?(file)
	else
		puts "[\e[32m+\e[0m] Results added at #{file}"
	end
end



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



def process_urls(file_to_scan, output_file = nil, &block)
	queue = Queue.new
	urls = File.readlines(file_to_scan).map(&:strip).reject(&:empty?)
	urls.each { |url| queue << url }

	num_threads = [Etc.nprocessors, $CONFIG['n_threads']].min
	mutex = Mutex.new
	results = []

	(1..num_threads).map do
		Thread.new do
			while !queue.empty?
				url = queue.pop(true) rescue nil
				next unless url

				response = check_url(url)
				next unless response

				result = block.call(response, url)
				if result
					mutex.synchronize do
						output_file ? File.write(output_file, "#{result}\n", mode: 'a') : results << result
					end
				end
			end
		end
	end.each(&:join)

	results
end



def check_url(url, retries = 2)
	uri = URI.parse(url)
	response = nil

	begin
		http = Net::HTTP.new(uri.host, uri.port)
		http.open_timeout = 3
		http.read_timeout = 3

		if uri.scheme == 'https'
			http.use_ssl = true
			http.verify_mode = OpenSSL::SSL::VERIFY_NONE
		end

		request = Net::HTTP::Get.new(uri.request_uri)
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
def process_urls_for_code(file_to_scan, output_file, status_code)
	process_urls(file_to_scan, output_file) do |response, url|
		url if response.code.to_i == status_code
	end
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
	live_urls = process_urls(file_path) do |response, url|
		if response.is_a?(Net::HTTPSuccess)
			puts "[\e[32m+\e[0m] Alive URL: #{url}"
			url
		elsif response.code.to_i == 404
			puts "[\e[31m+\e[0m] 404 Not Found: #{url}"
			nil
		else
			puts "[\e[31m+\e[0m] Dead URL: #{url}"
			nil
		end
	end

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



def identify_technology(response)
	return {} unless response.is_a?(Net::HTTPSuccess)
	body = response.body.downcase
  
	{
		wp: body.include?('wordpress') || body.include?('/wp-content/'),
		drupal: body.include?('drupal') || body.include?('/sites/all/'),
		iis: response['Server']&.include?('IIS')
	}
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

	# Write all the techs identified
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
	# - [ ] Vedere webanalyze

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



def search_for_vulns(params, num_threads = [Etc.nprocessors, $CONFIG['n_threads']].min)

	file_to_scan = params[:file]

	system "mkdir output" if !File.directory?('output')

	o_sanitized = file_to_scan.gsub(/[^\w\s]/, '_')

	# Get only 200s
	process_urls_for_code(file_to_scan, "output/200_#{o_sanitized}.txt", 200)

	# :: Mantra ::
	puts "\n[\e[34m*\e[0m] Searching for secrets with Mantra"
	system "cat output/200_#{o_sanitized}.txt | grep -Evi '\\.(svg|png|pngx|gif|gifx|ico|jpg|jpgx|jpeg|jfif|jpg-large|bmp|mp3|mp4|ttf|woff|ttf2|woff2|eot|eot2|swf2|css|pdf|webp|tif)' | mantra -t #{$CONFIG['n_threads']} | grep \"\\[+\\]\" | tee output/mantra_results_#{o_sanitized}.txt"
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



def get_to_burp_fun(params, num_threads = [Etc.nprocessors, $CONFIG['n_threads']].min)
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
	system "mkdir output" unless File.directory?('output')
	file = params[:file]
	allsubs_file = "output/allsubs_#{file}"
	File.write(allsubs_file, "") unless File.exist?(allsubs_file)

	File.open(file, 'r').each_line do |f|
		target = f.chomp
		next if target.empty?

		puts "\n[\e[34m*\e[0m] Starting asset enumeration for #{target}"

		# Temporary files
		amass_results = "output/#{target}_amass_results.txt"
		subfinder_out = "output/#{target}_subfinder.txt"
		github_out = "output/#{target}_github.txt"
		gobuster_out = "output/#{target}_gobuster.txt"
		final_tmp = "output/#{target}_final.tmp"

		# Cleanup previous runs
		[amass_results, subfinder_out, github_out, gobuster_out, final_tmp].each do |f|
			File.delete(f) if File.exist?(f)
		end

		# Parallel execution setup
		threads = []
		mutex = Mutex.new

		# Amass thread
		threads << Thread.new do
			amass_mode = params[:gb_opt] == "y" ? "-brute -active" : "-passive"
			system("amass enum #{amass_mode} -d #{target} -v -dns-qps 300")
		end

		# Subfinder thread
		threads << Thread.new do
			system("subfinder -d #{target} -all -o #{subfinder_out}")
		end

		# GitHub subdomains thread
		if $CONFIG['github_token'] && $CONFIG['github_token'] != "YOUR_GITHUB_TOKEN_HERE"
			threads << Thread.new do
				system("github-subdomains -t #{$CONFIG['github_token']} -d #{target} -o #{github_out}")
			end
		end

		# Gobuster DNS thread (heavy mode only)
		if params[:gb_opt] == "y"
			threads << Thread.new do
				system("gobuster dns -d #{target} -w all.txt -t #{$CONFIG['n_threads']} -o #{gobuster_out}")
			end
		end

		# Wait for all parallel tasks to complete
		threads.each(&:join)

		# Now query Amass database with oam_subs
		system("oam_subs -names -d #{target} | tee #{amass_results}")

		# Merge all results
		[amass_results, subfinder_out, github_out, gobuster_out].each do |src|
			next unless File.exist?(src)
			
			File.foreach(src) do |line|
				line.chomp!
				next if line.empty?
				
				mutex.synchronize do
					File.open(final_tmp, 'a') { |f| f.puts(line) }
				end
			end
		end

		# Validate and deduplicate
		if File.exist?(final_tmp)
			valid_subs = File.readlines(final_tmp)
											 .map(&:chomp)
											 .uniq
											 .select { |sub| IPSocket.getaddress(sub) rescue false }

			final_file = "output/#{target}.txt"
			File.write(final_file, valid_subs.join("\n"))
			adding_anew(final_file, allsubs_file)
		end

		# Cleanup
		[amass_results, subfinder_out, github_out, gobuster_out, final_tmp, amass_results].each do |f|
			File.delete(f) if File.exist?(f)
		end
	end

	# == HTTP Discovery ==
	http_file = "output/http_#{file}"
	temp_httpx = "output/http_#{file}_httpx.tmp"
	temp_httprobe = "output/http_#{file}_httprobe.tmp"

	File.write(http_file, "") unless File.exist?(http_file)

	puts "\n[\e[34m*\e[0m] Searching for web services output/allsubs_#{file}"

	threads = []

	threads << Thread.new do
	  system("cat output/allsubs_#{file} | httpx-toolkit -t #{$CONFIG['n_threads']} -p #{$CONFIG['ports']} -o #{temp_httpx}")
	end

	threads << Thread.new do
	  system("cat output/allsubs_#{file} | httprobe -p http:81 -p http:3000 -p https:3000 -p http:3001 -p https:3001 -p http:8000 -p http:8080 -p https:8443 -c 100 | tee #{temp_httprobe}")
	end

	threads.each(&:join)

	adding_anew(temp_httpx, http_file)
	adding_anew(temp_httprobe, http_file)

	# Cleanup
	[temp_httpx, temp_httprobe].each { |f| File.delete(f) if File.exist?(f) }
	puts "[\e[32m+\e[0m] Results saved as #{http_file}"

	# == naabu ==
	if params[:gb_opt] == "y"
		puts "\n[\e[34m*\e[0m] Searching for more open ports..."
		ports_file = "output/ports_#{file}"
		hidden_temp = "output/http_hidden_#{file}.tmp"

		system("naabu -v -list output/allsubs_#{file} -p - -exclude-ports #{$CONFIG['ports']} -c 1000 -rate 7000 -stats -o #{ports_file}")
		delete_if_empty(ports_file)

		if File.exist?(ports_file)
			port_threads = []
			port_threads << Thread.new { system("cat #{ports_file} | httpx-toolkit -t #{$CONFIG['n_threads']} -o #{hidden_temp}_httpx") }
			port_threads << Thread.new { system("cat #{ports_file} | httprobe | anew #{hidden_temp}_httprobe") }
			port_threads.each(&:join)

			# Combine results
			adding_anew("#{hidden_temp}_httpx", http_file)
			adding_anew("#{hidden_temp}_httprobe", http_file)
			
			# Cleanup
			[hidden_temp + '_httpx', hidden_temp + '_httprobe'].each { |f| File.delete(f) if File.exist?(f) }
		end
	end

	# == Interesting subs ==

	puts "\n[\e[34m*\e[0m] Showing some interesting subdomains found"
	system "cat output/allsubs_#{file} | grep -E \"jenkins|jira|gitlab|github|sonar|bitbucket|travis|circleci|eslint|pylint|junit|testng|pytest|jest|selenium|appium|postman|newman|cypress|seleniumgrid|artifactory|nexus|ansible|puppet|chef|deploybot|octopus|prometheus|grafana|elk|slack|admin|geoservice|teams\" | sort -u | tee output/interesting_subdomains_#{file}"
	system "cat output/http_#{file} | grep -E \"jenkins|jira|gitlab|github|sonar|bitbucket|travis|circleci|eslint|pylint|junit|testng|pytest|jest|selenium|appium|postman|newman|cypress|seleniumgrid|artifactory|nexus|ansible|puppet|chef|deploybot|octopus|prometheus|grafana|elk|slack|admin|geoservice|teams\" | sort -u | anew output/interesting_subdomains_#{file}"
	delete_if_empty "output/interesting_subdomains_#{file}"

	send_telegram_notif("Asset enumeration for #{file} finished")
end



def webscreenshot_fun(params, num_threads = [Etc.nprocessors, $CONFIG['n_threads']].min)
	urls = File.readlines(params[:file]).map(&:chomp)
	queue = Queue.new
	urls.each { |url| queue << url }

	i = 0
	image_paths = []
	successful_urls = []
	
	system "mkdir -p output/webscreen"

	options = Selenium::WebDriver::Chrome::Options.new
	options.add_argument('--ignore-certificate-errors')
	options.add_argument('--disable-popup-blocking')
	options.add_argument('--disable-translate')
	options.add_argument('--ignore-certificate-errors-spki-list')
	options.add_argument('--window-size=2560,1440')
	options.add_argument('--headless=new')
	options.add_argument('--disable-gpu')
	options.add_argument('--no-sandbox')

	mutex = Mutex.new
	workers = []

	num_threads.times do
		workers << Thread.new do
			begin
				driver = Selenium::WebDriver.for(:chrome, options: options)
				
				while !queue.empty? && url = queue.pop(true) rescue nil
					begin
						driver.navigate.to(url)
						sleep 1

						sanitized = url.gsub(/[^\w\.-]/, '_')[0..150]
						image_path = "output/webscreen/#{sanitized}.png"

						driver.save_screenshot(image_path)

						mutex.synchronize do
							i += 1
							puts "[\e[32m#{i}\e[0m] Screenshot: #{image_path}"
							image_paths << image_path
							successful_urls << url
						end
					rescue => e
						mutex.synchronize do
							puts "[\e[31m!\e[0m] Error on #{url}: #{e.message.gsub(/\n/, ' ')}"
						end
					end
				end
				
			ensure
				driver.quit if defined?(driver) && driver
			end
		end
	end

	workers.each(&:join)

	# HTML gallery creation
	File.open('output/gallery.html', 'w') do |html|
		html.write('<!DOCTYPE html><html><head><title>Screenshots</title>')
		html.write('<style>.screenshot{margin:10px;float:left;width:300px;}</style>')
		html.write('</head><body>')
		
		image_paths.each_with_index do |path, idx|
			html.write(%Q(
				<div class="screenshot">
					<a href="#{path}" target="_blank">
						<img src="#{path}" width="280" alt="#{successful_urls[idx]}">
					</a>
					<div>#{successful_urls[idx]}</div>
				</div>
			))
		end
		
		html.write('</body></html>')
	end

	puts "[\e[32m+\e[0m] Gallery created: output/gallery.html"
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

	# Waymore
	
	extract_main_domains("output/allUrls_#{file_sanitized}", "output/_tmp_domains_#{file_sanitized}")
	File.open("output/_tmp_domains_#{file_sanitized}",'r').each_line do |f|
		target = f.strip
		puts "\n[\e[34m*\e[0m] Finding more endpoints for #{target} with WayMore\n"
		system "waymore -i #{target} -c /home/kali/.config/waymore/config.yml -f -p 5 -mode U -oU output/#{target}_waymore.txt"
		sleep(30)
		remove_using_scope(file, "output/#{target}_waymore.txt")
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
			remove_using_scope(file, "output/github-endpoints_#{file_sanitized}")
			clean_urls "output/github-endpoints_#{file_sanitized}"
			adding_anew("output/github-endpoints_#{file_sanitized}", "output/allUrls_#{file_sanitized}")
		end
	end

	# JS file analysis
	puts "\n[\e[34m*\e[0m] Searching for JS files"
	system "cat output/allUrls_#{file_sanitized} | grep \"\\.js$\" | tee output/_tmpAllJSUrls_#{file_sanitized}"
	system "cat output/allUrls_#{file_sanitized} | getJS -threads #{$CONFIG['n_threads']} -complete -resolve | anew output/_tmpAllJSUrls_#{file_sanitized}"
	remove_using_scope(file, "output/_tmpAllJSUrls_#{file_sanitized}")
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
