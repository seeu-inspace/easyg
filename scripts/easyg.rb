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
require 'fileutils'

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

	FileUtils.rm_f(file_tmp)
end



def delete_if_empty(file)
	if !File.exist?(file) || File.zero?(file)
		puts "[\e[36m+\e[0m] No result found"
		FileUtils.rm_f(file)
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

	File.open(input_file, 'r').each_line do |line|
		line.strip!
		next if line.empty?

		begin
			uri = URI.parse(line)
			host = uri.host&.downcase
			next if host.nil? || host.empty?

			# Special case handling for country-code TLDs
			parts = host.split('.')

			# IP address or single-word domain
			main_domain = if parts.length == 1 || host.match?(/\A\d{1,3}(\.\d{1,3}){3}\z/)
				host
			elsif parts[-2].match?(/^(co|com|org|net|gov|edu|ac)$/) && parts.length > 2
				# Handle special TLD patterns (e.g. .co.uk, .ac.jp)
				"#{parts[-3]}.#{parts[-2]}.#{parts[-1]}"
			else
				# Standard domain format
				"#{parts[-2]}.#{parts[-1]}"
			end

			domains.add(main_domain)
		rescue URI::InvalidURIError
			next
		end
	end

	File.open(output_file, 'w') { |file| domains.each { |domain| file.puts(domain) } }
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
			puts "[\e[31m!\e[0m] Failed to send notification. Response: [\e[31m#{response.code} #{response.message}\e[0m]"
		end
	rescue Net::OpenTimeout, Net::ReadTimeout => e
		puts "[\e[31m!\e[0m] Network timeout error: #{e.message}"
		if retries > 0
			retries -= 1
			puts "[\e[33m*\e[0m] Retrying... (#{3 - retries} attempts left)"
			sleep(1)
			retry
		end
	rescue SocketError => e
		puts "[\e[31m!\e[0m] Socket error: #{e.message}"
	rescue StandardError => e
		puts "[\e[31m!\e[0m] An unexpected error occurred: #{e.message}"
	end
end



# :: Functions to check URLs ::



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
		puts "[\e[31m!\e[0m] ERROR checking URL #{url}: #{e.message}"
		return nil
	end

	response
end



def process_urls(file_to_scan, output_file = nil, &block)
	queue = Queue.new
	urls = File.readlines(file_to_scan).map(&:strip).reject(&:empty?)
	urls.each { |url| queue << url }

	num_threads = $CONFIG['n_threads']
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



def file_sanitization(file_path)
	return puts "[\e[31m+\e[0m] File not found: #{file_path}" unless File.exist?(file_path)

	sanitized_lines = []

	File.foreach(file_path) do |line|
		line.strip!
		next if line.empty?

		if line.start_with?("http")
			begin
				uri = URI.parse(line)

				# Encodes URL components while preserving existing percent-encoding:
				# - Splits segments like "%20" to avoid double-encoding
				# - Handles path, query, and fragment separately
				encode_component = ->(component) {
					component.gsub(/%[0-9A-Fa-f]{2}/) { |match| match }
									 .split(/(%[0-9A-Fa-f]{2})/)
									 .map { |segment| segment.match?(/%[0-9A-Fa-f]{2}/) ? segment : URI.encode_www_form_component(segment).gsub('%', '%25') }
									 .join
				}

				encoded_path = uri.path.split('/').map { |segment| encode_component.call(segment) }.join('/')
				encoded_query = uri.query ? uri.query.split('&').map { |param| param.split('=', 2).map { |part| encode_component.call(part) }.join('=') }.join('&') : nil
				encoded_fragment = uri.fragment ? encode_component.call(uri.fragment) : nil

				sanitized_url = URI::Generic.build(
					scheme: uri.scheme,
					userinfo: uri.user,
					host: uri.host,
					port: uri.port,
					path: encoded_path,
					query: encoded_query,
					fragment: encoded_fragment
				).to_s

				sanitized_lines << sanitized_url
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
	filtered = []
	File.foreach(file_path) do |line|
		filtered << line if line.match?(/^(http|https):/)
	end
	File.write(file_path, filtered.join)

	# Step 3: Process the file with urless to deduplicate URLs
	puts "[\e[34m*\e[0m] Running urless to deduplicate URLs..."
	if system("urless -i #{file_path} -o #{file_path}.tmp")
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
	filtered_urls.reject! do |url|
		next false unless url.include?('?')
		contains_only_tracking_params?(url)
	end
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
		system("firefox \"#{target}\"")
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
	FileUtils.mkdir_p('output')
	file = params[:file]
	allsubs_file = "output/allsubs_#{file}"
	File.write(allsubs_file, "") unless File.exist?(allsubs_file)

	File.open(file, 'r').each_line do |f|
		target = Shellwords.escape(f.chomp)
		next if target.empty?

		puts "\n[\e[34m*\e[0m] Starting asset enumeration for #{target}"

		# Temporary files
		amass_results = "output/#{target}_amass_results.txt"
		subfinder_out = "output/#{target}_subfinder.txt"
		github_out = "output/#{target}_github.txt"
		gobuster_out = "output/#{target}_gobuster.txt"
		crtsh_out = "output/#{target}_crtsh.txt"
		final_tmp = "output/#{target}_final.tmp"

		# Cleanup previous runs
		[amass_results, subfinder_out, github_out, gobuster_out, crtsh_out, final_tmp].each do |f|
			FileUtils.rm_f(f)
		end

		# Parallel execution setup
		threads = []
		mutex = Mutex.new

		# Amass thread
		threads << Thread.new do
			amass_mode = params[:gb_opt] == "y" ? "-brute -active" : "-passive -timeout 15"
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

		# crt.sh thread
		threads << Thread.new do
			begin
				uri = URI.parse("https://crt.sh/?q=#{target}&output=json")
				response = Net::HTTP.get_response(uri)
				crtsh = JSON.parse((response.body).to_s)

				File.open(crtsh_out, "w") do |file|
					crtsh.each do |f|
						if !f["common_name"].nil?
							subdomain = f["common_name"].gsub('*.','').to_s
							puts subdomain
							file.puts(subdomain) if subdomain.include?(".#{target}")
						end
					end
				end
			rescue Exception => e
				puts "[\e[31m!\e[0m] ERROR: #{e.message}"
			end
		end

		# Wait for all parallel tasks to complete
		threads.each(&:join)

		# Now query Amass database with oam_subs
		system("oam_subs -names -d #{target} | tee #{amass_results}")

		# Merge all results
		[amass_results, subfinder_out, github_out, gobuster_out, crtsh_out].each do |src|
			adding_anew(src, final_tmp)
		end

		# Validate and deduplicate
		if File.exist?(final_tmp)
			valid_subs = File.readlines(final_tmp)
							.map(&:chomp)
							.uniq
							.select { |sub| IPSocket.getaddress(sub) rescue false }
			final_file = "output/#{target}.txt"
			File.write(final_file, valid_subs.join("\n"))
			FileUtils.rm_f(final_tmp)
			adding_anew(final_file, allsubs_file)
		end

	end

	# == HTTP Discovery ==
	http_file = "output/http_#{file}"
	temp_httpx = "output/http_#{file}_httpx.tmp"
	temp_httprobe = "output/http_#{file}_httprobe.tmp"

	File.write(http_file, "") unless File.exist?(http_file)

	puts "\n[\e[34m*\e[0m] Searching for web services output/allsubs_#{file}"

	threads = []
	threads << Thread.new { system("cat output/allsubs_#{file} | httpx-toolkit -t #{$CONFIG['n_threads']} -p #{$CONFIG['ports']} -o #{temp_httpx}") }
	threads << Thread.new { system("cat output/allsubs_#{file} | httprobe -p http:81 -p http:3000 -p https:3000 -p http:3001 -p https:3001 -p http:8000 -p http:8080 -p https:8443 -c 100 | tee #{temp_httprobe}") }
	threads.each(&:join)

	adding_anew(temp_httpx, http_file)
	adding_anew(temp_httprobe, http_file)

	# Cleanup
	[temp_httpx, temp_httprobe].each { |f| FileUtils.rm_f(f) }
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
			port_threads << Thread.new { system("cat #{ports_file} | httprobe | tee #{hidden_temp}_httprobe") }
			port_threads.each(&:join)

			# Combine results
			adding_anew("#{hidden_temp}_httpx", http_file)
			adding_anew("#{hidden_temp}_httprobe", http_file)

		end
	end

	# == Interesting subs ==

	keywords = %w[jenkins jira gitlab github sonar bitbucket travis circleci eslint pylint junit testng pytest jest selenium appium postman newman cypress seleniumgrid artifactory nexus ansible puppet chef deploybot octopus prometheus grafana elk slack admin geoservice teams]
	pattern = Regexp.union(keywords.map { |k| Regexp.new(Regexp.escape(k), Regexp::IGNORECASE) })

	# Process allsubs file and write to interesting_subdomains
	allsubs_file = "output/allsubs_#{file}"
	interesting_file = "output/interesting_subdomains_#{file}"

	if File.exist?(allsubs_file)
		allsubs_matches = File.readlines(allsubs_file).grep(pattern).map(&:chomp).uniq.sort
		File.write(interesting_file, allsubs_matches.join("\n") + "\n")
	end

	# Process http file and append to interesting_subdomains
	http_file = "output/http_#{file}"
	if File.exist?(http_file)
		http_matches = File.readlines(http_file).grep(pattern).map(&:chomp).uniq.sort
		File.open(interesting_file, 'a') do |f|
			f.puts(http_matches.join("\n"))
		end
	end

	delete_if_empty(interesting_file)

	send_telegram_notif("Asset enumeration for #{file} finished")
end



def webscreenshot_fun(params, num_threads = $CONFIG['n_threads'])
	urls = File.readlines(params[:file]).map(&:chomp)
	queue = Queue.new
	urls.each { |url| queue << url }

	i = 0
	image_paths = []
	successful_urls = []
	
	FileUtils.mkdir_p('output/webscreen')

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
	FileUtils.mkdir_p('output')

	targets = File.readlines(file).map(&:chomp)
	target_queue = Queue.new
	targets.each { |t| target_queue << t }
	mutex = Mutex.new

	# Thread pool for target processing
	target_threads = Array.new([targets.size, Etc.nprocessors].min) do
		Thread.new do
			while !target_queue.empty? && target = target_queue.pop(true) rescue nil
				target_sanitized = target.gsub(/^https?:\/\//, '').gsub(/:\d+$/, '').gsub('/', '')
				target_tmp = target_sanitized

				# Run katana and gau in parallel
				katana_file = "output/#{target_sanitized}_tmp.txt"
				gau_file = "output/#{target_sanitized}_gau.txt"

				threads = []
				threads << Thread.new do
					system("katana -u #{Shellwords.escape(target)} -jc -jsl -hl -kf -aff -d 3 -p 25 -c 25 -fs fqdn -H \"Cookie: #{$CONFIG['cookie']}\" -o #{katana_file}")
				end

				threads << Thread.new do
					system("echo #{Shellwords.escape(target)} | gau --blacklist svg,png,gif,ico,jpg,jpeg,jfif,jpg-large,bmp,mp3,mp4,ttf,woff,ttf2,woff2,eot,eot2,swf,swf2,css --fc 404 --threads #{$CONFIG['n_threads']} --verbose --o #{gau_file}")
				end

				threads.each(&:join)

				# Merge results
				mutex.synchronize do
					adding_anew(gau_file, katana_file)
				end

				# ParamSpider
				unless target_sanitized == target_tmp
					system("paramspider -d #{Shellwords.escape(target_sanitized)}")
					adding_anew("results/#{target_sanitized}.txt", katana_file)
				end

				# Clean and merge
				mutex.synchronize do
					clean_urls(katana_file)
					adding_anew(katana_file, "output/allUrls_#{file_sanitized}")
					puts "[\e[32m+\e[0m] Results for #{target} saved in output/allUrls_#{file_sanitized}"
				end
			end
		end
	end
	target_threads.each(&:join)

	extract_main_domains("output/allUrls_#{file_sanitized}", "output/_tmp_domains_#{file_sanitized}")
	domains = File.readlines("output/_tmp_domains_#{file_sanitized}").map(&:chomp)
	domain_queue = Queue.new
	domains.each { |d| domain_queue << d }
  
	domain_threads = Array.new([domains.size, Etc.nprocessors].min) do
		Thread.new do
			while !domain_queue.empty? && domain = domain_queue.pop(true) rescue nil
				# Waymore processing
				waymore_file = "output/#{domain}_waymore.txt"
				system("waymore -i #{domain} -c /home/kali/.config/waymore/config.yml -f -p 5 -mode U -oU #{waymore_file}")
				remove_using_scope(file, waymore_file)
				clean_urls(waymore_file)
				mutex.synchronize { adding_anew(waymore_file, "output/allUrls_#{file_sanitized}") }
		
				# GitHub endpoints processing
				if $CONFIG['github_token'] && $CONFIG['github_token'] != "YOUR_GITHUB_TOKEN_HERE"
					github_file = "output/github-endpoints_#{domain}.txt"
					system("python ~/Tools/web-attack/github-search/github-endpoints.py -d #{domain} -t #{$CONFIG['github_token']} | tee #{github_file}")
					remove_using_scope(file, github_file)
					clean_urls(github_file)
					mutex.synchronize { adding_anew(github_file, "output/allUrls_#{file_sanitized}") }
				end
			end
		end
	end
	domain_threads.each(&:join)

	# JS file analysis
	puts "\n[\e[34m*\e[0m] Searching for JS files"
	js_lines = []
	File.foreach("output/allUrls_#{file_sanitized}") do |line|
		line.chomp!
		begin
			uri = URI.parse(line)
			if uri.path && File.extname(uri.path.downcase) == '.js'
				js_lines << line
			end
		rescue URI::InvalidURIError
			next
		end
	end
	File.open("output/allJSUrls_#{file_sanitized}", 'w') do |f|
		js_lines.each { |line| f.puts(line) }
	end
	system("cat output/allUrls_#{file_sanitized} | getJS -threads #{$CONFIG['n_threads']} -complete -resolve | tee output/getJS_#{file_sanitized}")
	adding_anew("output/getJS_#{file_sanitized}","output/allJSUrls_#{file_sanitized}")
	remove_using_scope(file, "output/allJSUrls_#{file_sanitized}")
	clean_urls "output/allJSUrls_#{file_sanitized}"
	puts "[\e[32m+\e[0m] Results saved as output/allJSUrls_#{file_sanitized}"

	# Find new URLs from the JS files
	puts "\n[\e[34m*\e[0m] Finding more endpoints from output/allJSUrls_#{file_sanitized} with xnLinkFinder"
	system("sed -E 's~^[a-zA-Z]+://([^:/]+).*~\\1~' output/allUrls_#{file_sanitized} | grep -v \"^*\\.\" | sed '/^\\s*$/d' | grep '\\.' | sort | uniq > output/tmp_scope.txt")
	system("xnLinkFinder -i output/allJSUrls_#{file_sanitized} -sf output/tmp_scope.txt -p #{$CONFIG['n_threads']} -vv -insecure -sp #{file} -o output/xnLinkFinder_#{file_sanitized}")
	clean_urls "output/xnLinkFinder_#{file_sanitized}"
	adding_anew("output/allJSUrls_#{file_sanitized}", "output/allUrls_#{file_sanitized}")
	adding_anew("output/xnLinkFinder_#{file_sanitized}", "output/allUrls_#{file_sanitized}")

	# Final
	FileUtils.rm_f("output/_tmp_domains_#{file_sanitized}")
	FileUtils.rm_f("output/tmp_scope.txt")
	FileUtils.rm_f("parameters.txt")
	FileUtils.rm_rf("results/")
	remove_using_scope(file, "output/allUrls_#{file_sanitized}")
	puts "[\e[32m+\e[0m] Results for #{file} saved as output/allUrls_#{file_sanitized}"
	send_telegram_notif("Crawl-local for #{file} finished")

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
	"assetenum" => {
		action: ->(params) { assetenum_fun(params) },
		description: "Asset enumeration & web service discovery"
	},
	"crawl-local" => {
		action: ->(params) { crawl_local_fun(params) },
		description: "Crawl for every entry in <file_input> and save the results in local"
	},
	"do-everything" => {
		action: ->(params) { do_everything_fun(params) },
		description: "Asset enumeration > Crawl Locally"
	},
	"get-to-burp" => {
		action: ->(params) { get_to_burp_fun(params) },
		description: "For every entry in <file_input>, send a GET request using Burp Suite as a proxy"
	},
	"firefox" => {
		action: ->(params) { firefox_fun(params) },
		description: "Open every entry in <file_input> with Firefox"
	},
	"webscreenshot" => {
		action: ->(params) { webscreenshot_fun(params) },
		description: "Take a screenshot for every entry in <file_input> and make a gallery"
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

		options_that_need_file = ["firefox", "get-to-burp", "assetenum", "webscreenshot", "crawl-local", "do-everything"]
		if options_that_need_file.include?(option)
			print "\e[93m┌─\e[0m Enter the file target:\n\e[93m└─\e[0m "
			params[:file] = gets.chomp
			puts "\n" if option == "firefox" || option == "get-to-burp" || option == "webscreenshot"
		end

		if option == "assetenum" || option == "do-everything"
			print "\n\e[93m┌─\e[0m Heavy mode? [y/n]:\n\e[93m└─\e[0m "
			params[:gb_opt] = gets.chomp
			puts "\n"
		end

		option_params[option] = params

		option_actions[option][:action].call(option_params[option])

	else
		puts "[\e[31m!\e[0m] Invalid option selected"
	end

rescue Interrupt
	puts "\n[\e[31m!\e[0m] Script interrupted by user. Exiting..."
	exit
rescue StandardError => e
	puts "\n[\e[31m!\e[0m] An error occurred: #{e.message}"
	puts e.backtrace
	send_telegram_notif 'easyg.rb crashed'
	exit 1
end
