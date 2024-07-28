#!/usr/bin/env ruby

require 'uri'
require 'net/http'
require 'json'
require 'socket'
require 'webdrivers'
require 'selenium-webdriver'
require 'yaml'
require 'thread'

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
	domains = []

	def extract_main_domain(url)
		begin
			uri = URI.parse(url)
			host = uri.host.downcase
			parts = host.split('.')

			return host if parts.length == 1 || parts[-1] =~ /\d+/

			return "#{parts[-2]}.#{parts[-1]}"
		rescue Exception => e
			nil
		end
	end

	File.open(input_file, 'r').each_line do |line|
		line.strip!
		next if line.empty?

		domain = extract_main_domain(line)

		unless domains.include?(domain)
			domains << domain
		end
	end

	File.open(output_file, 'w') do |file|
		domains.each do |domain|
			file.puts domain unless domain.nil? || domain.empty?
		end
	end

end



def send_telegram_notif(message)

	if !$CONFIG['telegram'].nil? || $CONFIG['telegram'] != "YOUR_TELEGRAM_TOKEN_HERE" || !$CONFIG['telegram_chat_id'].nil? || $CONFIG['telegram_chat_id'] != "YOUR_TELEGRAM_CHAT_ID_HERE"
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
end



# :: Functions to check URLs ::



def check_url(url)
	uri = URI.parse(url)
	response = nil

	http = Net::HTTP.new(uri.host, uri.port)
	if uri.scheme == 'https'
		http.use_ssl = true
		http.verify_mode = OpenSSL::SSL::VERIFY_NONE
	end

	request = Net::HTTP::Get.new(uri.request_uri)
	response = http.request(request)

	response
rescue => e
	puts "[\e[31m+\e[0m] Error checking URL #{url}: #{e.message}"
	nil
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
end



def get_content_type(url)
	uri = URI.parse(url)
	response = nil

	http = Net::HTTP.new(uri.host, uri.port)
	if uri.scheme == 'https'
		http.use_ssl = true
		http.verify_mode = OpenSSL::SSL::VERIFY_NONE
	end

	request = Net::HTTP::Get.new(uri.request_uri)
	response = http.request(request)

	if response.is_a?(Net::HTTPSuccess)
		return response['content-type']
	else
		return nil
	end
rescue => e
	return nil
end



def contains_only_tracking_params?(url)
	uri = URI.parse(url)
	return false if uri.query.nil?

	tracking_params = %w[utm_source utm_medium utm_campaign utm_term utm_content gclid fbclid]
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
		puts "[\e[31m+\e[0m] Error processing file"
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



def replace_param_with_fuzz(url)
	uri = URI.parse(url)
	params = URI.decode_www_form(uri.query || '')
	params.map! { |param, value| [param, 'FUZZ'] }
	uri.query = URI.encode_www_form(params)
	uri.to_s
end



def remove_using_scope(scope_file, url_file)
	scope_urls = File.readlines(scope_file).map(&:strip)
	urls = File.readlines(url_file).map(&:strip)
	
	scope_hosts = scope_urls.map do |url|
		begin
			URI(url).host
		rescue => e
			puts "[\e[31m+\e[0m] ERROR: #{e.message}"
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
	puts "[\e[31m+\e[0m] ERROR: #{e.message}"
end



def clean_urls(file_path, num_threads = $CONFIG['n_threads'])
	puts "[\e[34m*\e[0m] Starting URL cleaning process..."

	# Setp 1: Clean file
	puts "[\e[34m*\e[0m] Cleaning file..."
	file_sanitization file_path

	# Step 2: Filter only valid URLs using sed
	puts "[\e[34m*\e[0m] Filtering valid URLs..."
	system "sed -i -E '/^(http|https):/!d' #{file_path}"

	# Step 3: Remove useless URLs like _Incapsula_Resource
	puts "[\e[34m*\e[0m] Removing useless URLs..."
	urls = File.readlines(file_path).map(&:strip).reject(&:empty?)
	filtered_urls = urls.reject { |url| url.include?('_Incapsula_Resource') }
	puts "[\e[32m+\e[0m] Useless URLs removed"

	# Step 4: Remove URLs with only tracking parameters
	puts "[\e[34m*\e[0m] Removing URLs with only tracking parameters..."
	filtered_urls.reject! { |url| contains_only_tracking_params?(url) }
	puts "[\e[32m+\e[0m] URLs with only tracking parameters removed"

	# Step 5: Remove dead links and 404 URLs
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

	# Step 6: Overwrite the input file with the cleaned URLs
	puts "[\e[34m*\e[0m] Writing cleaned URLs to file..."
	File.open(file_path, 'w') { |file| file.puts(live_urls) }
	puts "[\e[32m+\e[0m] Cleaned URLs written to #{file_path}"

	# Step 7: Process the file with urless
	puts "[\e[34m*\e[0m] Running urless to deduplicate URLs..."
	urless_command = "urless -i #{file_path} -o #{file_path}.tmp"
	if system(urless_command)
		File.rename("#{file_path}.tmp", file_path)
		puts "[\e[32m+\e[0m] Urless processing complete, deduplicated URLs written to #{file_path}"
	else
		puts "[\e[31m+\e[0m] Error running urless"
	end
end



# :: Functions to identify technologies ::



def is_wordpress?(response)
	return false unless response.is_a?(Net::HTTPSuccess)
	body = response.body

	# WordPress detection regexes from the Nuclei template
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



def identify_technology(file_to_scan, output_file, num_threads = $CONFIG['n_threads'])
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
					next unless url

					response = check_url(url)
					if response && is_wordpress?(response)
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
end



# :: Functions to find vulnerabilities ::



def search_confidential_files(file_type, file_to_scan)
	puts "\n[\e[34m*\e[0m] Searching for possible confidential #{file_type.upcase}s"
	
	output_file = "output/reserved#{file_type.upcase}s_#{file_to_scan.gsub("/", "")}"

	# Construct the command to search for confidential files
	command = <<~BASH
		for i in `cat #{file_to_scan} | grep -Ea '\\.#{file_type}'`; do
			if curl -s "$i" | #{file_type == 'pdf' ? 'pdftotext -q - - | ' : ''}grep -Eaiq 'internal use only|usage interne uniquement|confidential|confidentielle|restricted|restreinte|password|credentials|connection string|MONGO_URI'; then
				echo $i | tee -a #{output_file};
			fi;
		done
	BASH

	system(command)
	delete_if_empty(output_file)
end



def waf_check(target)

	aggressive_wafs = [
		"Cloudflare",
		"Incapsula",
		"AWS Elastic Load Balancer",
		"Azure Front Door",
		"FortiWeb",
		"Palo Alto Next Gen Firewall",
		"PerimeterX",
		"Reblaze",
		"Sucuri CloudProxy",
		"ZScaler",
		"Akamai Kona Site Defender",
		"Barracuda",
		"F5 Networks BIG-IP",
		"Imperva SecureSphere",
		"DenyALL",
		"Citrix NetScaler",
		"Radware AppWall",
		"Sophos UTM Web Protection",
		"Wallarm"
	]

	output = `wafw00f "#{target}" -v`
	aggressive_waf = aggressive_wafs.any? { |waf| output.include?(waf) }

	if aggressive_waf
		puts "[\e[31m+\e[0m] Skipped, the target is behind an aggressive WAF"
	elsif output.include?('appears to be down')
		puts "[\e[31m+\e[0m] Skipped, the target appears to be down"
	else
		yield target
	end
end



def search_endpoints(file_input, output_file, num_threads = $CONFIG['n_threads'])
	urls = File.readlines(file_input).map(&:strip)

	swagger_paths = [
		"/swagger-ui/swagger-ui.js", "/swagger/swagger-ui.js", "/swagger-ui.js", "/swagger/ui/swagger-ui.js",
		"/swagger/ui/index", "/swagger/index.html", "/swagger-ui.html", "/swagger/swagger-ui.html",
		"/api/swagger-ui.html", "/api-docs/swagger.json", "/api-docs/swagger.yaml", "/api_docs",
		"/swagger.json", "/swagger.yaml", "/swagger/v1/swagger.json", "/swagger/v1/swagger.yaml",
		"/api/index.html", "/api/doc", "/api/docs/", "/api/swagger.json", "/api/swagger.yaml", "/api/swagger.yml",
		"/api/swagger/index.html", "/api/swagger/swagger-ui.html", "/api/api-docs/swagger.json",
		"/api/api-docs/swagger.yaml", "/api/swagger-ui/swagger.json", "/api/swagger-ui/swagger.yaml",
		"/api/apidocs/swagger.json", "/api/apidocs/swagger.yaml", "/api/swagger-ui/api-docs",
		"/api/doc.json", "/api/api-docs", "/api/apidocs", "/api/swagger", "/api/swagger/static/index.html",
		"/api/swagger-resources", "/api/swagger-resources/restservices/v2/api-docs", "/api/__swagger__/",
		"/api/_swagger_/", "/api/spec/swagger.json", "/api/spec/swagger.yaml", "/api/swagger/ui/index",
		"/__swagger__/", "/_swagger_/", "/api/v1/swagger-ui/swagger.json", "/api/v1/swagger-ui/swagger.yaml",
		"/swagger-resources/restservices/v2/api-docs", "/api/swagger_doc.json", "/docu", "/docs", "/swagger",
		"/api-doc", "/doc/", "/swagger-ui/springfox.js", "/swagger-ui/swagger-ui-standalone-preset.js",
		"/swagger-ui/swagger-ui/swagger-ui-bundle.js", "/webjars/swagger-ui/swagger-ui-bundle.js",
		"/webjars/swagger-ui/index.html"
	]

	git_paths = [
		"/.git/config", "/.git/HEAD", "/.git/index", "/.git/logs/HEAD"
	]

	queue = Queue.new
	urls.each { |url| queue << url }

	File.open(output_file, 'w') do |output|
		mutex = Mutex.new
		workers = Array.new(num_threads) do
			Thread.new do
				while !queue.empty? && url = queue.pop(true) rescue nil
					(swagger_paths + git_paths).each do |path|
						full_url = url.chomp("/") + path
						puts "[\e[34m*\e[0m] Checking URL: #{full_url}"
						response = check_url(full_url)

						if response && response.code.to_i == 200
							body = response.body

							if git_paths.include?(path)
								if path == "/.git/config"
									if (body.include?("[core]") || body.include?("[credentials]")) && !body.downcase.include?("<html") && !body.downcase.include?("<body")
										mutex.synchronize do
											output.puts("GIT: #{full_url}")
											puts "[\e[32m+\e[0m] Exposed .git/config found: #{full_url}"
										end
									end
								else
									if !body.downcase.include?("<html") && !body.downcase.include?("<body")
										mutex.synchronize do
											output.puts("GIT: #{full_url}")
											puts "[\e[32m+\e[0m] Exposed .git component found: #{full_url}"
										end
									end
								end
							else
								if body.include?("swagger:") || body.include?("Swagger 2.0") || body.include?("\"swagger\":") || body.include?("Swagger UI") || body.include?("loadSwaggerUI") || body.include?("**token**:") || body.include?('id="swagger-ui')
									mutex.synchronize do
										output.puts("SWAGGER: #{full_url}")
										puts "[\e[32m+\e[0m] Swagger endpoint found: #{full_url}"
									end
								end
							end
						end
					end
				end
			end
		end
		workers.each(&:join)
	end
end


# search_for_vulns but for base URLs
def base_url_s4v(file)

	system "mkdir output" if !File.directory?('output')

	file_sanitized = file.gsub("/", "")

	# Use some Nuclei templates
	puts "\n[\e[34m*\e[0m] Searching for subdomain takeovers with nuclei in #{file}"
	system "nuclei -l #{file} -tags takeover -stats -o output/nuclei_#{file_sanitized}"
	delete_if_empty "output/nuclei_#{file_sanitized}"

	# search for swaggers and git exposed
	puts "\n[\e[34m*\e[0m] Searching for swaggers and .git in #{file}"
	search_endpoints("#{file}", "output/endpoints_#{file_sanitized}")
	delete_if_empty "output/endpoints_#{file_sanitized}"

	# Search for 401 and 403 bypasses
	puts "\n[\e[34m*\e[0m] Searching for 401,403 and bypasses in #{file}"
	process_urls_for_code("#{file}", "output/40X_#{file_sanitized}", 403)
	process_urls_for_code("#{file}", "output/401_#{file_sanitized}", 401)
	system "cat output/401_#{file_sanitized} >> output/40X_#{file_sanitized} && rm output/401_#{file_sanitized}" if File.exists?("output/401_#{file_sanitized}")
	system "byp4xx -xB -m 2 -L output/40X_#{file_sanitized} | grep -v '==' |tee output/byp4xx_results_#{file_sanitized}"
	system "dirsearch -e * -x 404,403,401,400,429 -l output/40X_#{file_sanitized} --no-color --full-url -t #{$CONFIG['n_threads']} -o output/dirsearch_results_40X_#{file_sanitized}"
	remove_ansi "output/byp4xx_results_#{file_sanitized}"
	system "rm -rf reports/" if File.directory?('reports')

	# Search for WordPress websites and use WPScan
	puts "\n[\e[36m+\e[0m] Searching for technologies and specific vulnerabilities in #{file}"
	identify_technology("#{file}", "output/wp_#{file_sanitized}")
	delete_if_empty "output/wp_#{file_sanitized}"
	if File.exists?("output/wp_#{file_sanitized}")
		File.open("output/wp_#{file_sanitized}",'r').each_line do |f|
			target = f.chomp
			sanitized_target = target.gsub(/[^\w\s]/, '_')[0, 255]
			puts "\n[\e[34m*\e[0m] Starting WPScan for #{target}"
			if !$CONFIG['wpscan'].nil? || $CONFIG['wpscan'] != "YOUR_WPSCAN_TOKEN_HERE"
				system "wpscan --url #{target} --api-token #{$CONFIG['wpscan']} -t #{$CONFIG['n_threads']} --plugins-detection mixed -e vp,vt,cb,dbe,u1-10 --force -f cli-no-color --random-user-agent -o output/wpscan_#{sanitized_target}_#{file_sanitized}"
			else
				system "wpscan --url #{target} -t #{$CONFIG['n_threads']} --plugins-detection mixed -e vp,vt,cb,dbe,u1-10 --force -f cli-no-color --random-user-agent -o output/wpscan_#{sanitized_target}_#{file_sanitized}"
			end
		end
	end

	send_telegram_notif("Search for vulns for #{file} finished")
end



def search_for_vulns(params)

	file_to_scan = params[:file]

	system "mkdir output" if !File.directory?('output')

	o_sanitized = file_to_scan.gsub(/[^\w\s]/, '_')

	# Get only 200s
	process_urls_for_code(file_to_scan, "output/200_#{o_sanitized}.txt", 200)

	# :: Search for possible confidential files ::
	['pdf', 'txt', 'csv', 'xml', 'json', 'env'].each do |file_type|
		search_confidential_files(file_type, "output/200_#{o_sanitized}.txt")
	end

	# :: Mantra ::
	puts "\n[\e[34m*\e[0m] Searching for secrets with Mantra"
	system "cat output/200_#{o_sanitized}.txt | mantra -t #{$CONFIG['n_threads']} | grep \"\\[+\\]\" | tee output/mantra_results_#{o_sanitized}.txt"
	delete_if_empty "output/mantra_results_#{o_sanitized}.txt"
	remove_ansi "output/mantra_results_#{o_sanitized}.txt"

	# :: SocialHunter
	puts "\n[\e[34m*\e[0m] Searching for Brojen Link Hijaking with socialhunter"
	system "socialhunter -f output/200_#{o_sanitized}.txt -w 20 | grep \"Possible Takeover\" | tee output/socialhunter_results_#{o_sanitized}.txt"
	delete_if_empty "output/socialhunter_results_#{o_sanitized}.txt"

	if params[:gb_opt] == "y"
	
		system "mkdir output/dalfox" if !File.directory?('output/dalfox')
		system "mkdir output/ffuf_lfi" if !File.directory?('output/ffuf_lfi')
		system "mkdir output/ghauri" if !File.directory?('output/ghauri')

		## :: Grep only params ::
		system "cat #{file_to_scan} | grep -Evi '\\.(js|jsx|svg|png|pngx|gif|gifx|ico|jpg|jpgx|jpeg|bmp|mp3|mp4|ttf|woff|ttf2|woff2|eot|eot2|swf2|css|pdf|webp|tif|xlsx|xls|map)' | grep \"?\" | tee output/allParams_#{o_sanitized}.txt"

		# Search for XSS, LFI and SQLi
		puts "\n[\e[34m*\e[0m] Searching for XSSs, LFIs and SQLi"
		process_urls_for_code("output/allParams_#{o_sanitized}.txt", "output/200allParams_#{o_sanitized}.txt", 200)
		File.open("output/200allParams_#{o_sanitized}.txt",'r').each_line do |f|

			target = f.chomp
			sanitized_target = target.gsub(/[^\w\s]/, '_')[0, 255]
			content_type = get_content_type(target)

			if content_type && content_type.include?('text/html')
				system "dalfox url \"#{target}\" -C \"#{$CONFIG['cookie']}\" --ignore-return 302,404,403 --waf-evasion -o output/dalfox/#{sanitized_target}.txt"
			end

			waf_check(target) do |t|
				begin
					system "ghauri -u \"#{t}\" --batch --force-ssl | tee output/ghauri/ghauri_#{sanitized_target}.txt"
					t_fuzz = replace_param_with_fuzz(t)
					system "ffuf -u \"#{t_fuzz}\" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -ac -mc 200 -od output/ffuf_lfi/#{sanitized_target}/"
				rescue Exception => e
					puts "[\e[31m+\e[0m] ERROR: #{e.message}"
				end
			end

		end
		puts "[\e[32m+\e[0m] Results saved in the directories output/dalfox/ and output/ffuf_lfi/" if File.directory?('output/dalfox/') || File.directory?('output/ffuf_lfi/')

	end

	send_telegram_notif("Search for vulnerabilities for #{file_to_scan} finished")

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

	File.open(params[:file], 'r').each_line do |f|

		i += 1

		begin

			redirect = 3
			base_uri = URI.parse(f.chomp)

			res = request_fun(base_uri)

			puts "[\e[36m#{i.to_s}\e[0m] GET > #{f.chomp}"

			while res.is_a?(Net::HTTPRedirection) && redirect > 0
				location = res['location'].to_s
				puts "		Redirecting to > #{location}"
				uri = URI.parse(location)
				
				# If the URI is relative, make it absolute
				uri = base_uri + uri if uri.relative?
				
				res = request_fun(uri)
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
	system "cat output/allsubs_#{file} | httpx-toolkit -t #{$CONFIG['n_threads']} -p 80,443,81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3001,3002,3003,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9092,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672 -o output/http_#{file}"
	system "cat output/allsubs_#{file} | httprobe -p http:81 -p http:3000 -p https:3000 -p http:3001 -p https:3001 -p http:8000 -p http:8080 -p https:8443 -c 100 | anew output/http_#{file}"
	puts "[\e[32m+\e[0m] Results saved as output/http_#{file}"

	#== naabu ==
	if params[:gb_opt] == "y"
		puts "\n[\e[34m*\e[0m] Searching for more open ports in output/allsubs_#{file} with naabu"
		system "naabu -v -list output/allsubs_#{file} -p - -exclude-ports 80,443,81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3001,3002,3003,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9092,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672 -c 1000 -rate 7000 -stats -o output/ports_#{file}"
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
			puts "[\e[32m#{i}\e[0m] Screenshot saved as: #{image_path}"
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
			html.write("<img src=\"#{path.gsub('output/', '')}\" alt=\"Screenshot #{urls[index]}\" width=\"600\" height=\"400\">")
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

		puts "\n[\e[34m*\e[0m] Crawling #{target} with katana\n"
		system "katana -u #{target} -jc -jsl -hl -kf -aff -d 3 -p 25 -c 25 -fs fqdn -H \"Cookie: #{$CONFIG['cookie']}\" -proxy http://#{$CONFIG['proxy_addr']}:#{$CONFIG['proxy_port']}"

		puts "\n[\e[34m*\e[0m] Crawling #{target} with gau\n"
		system "echo #{target}| gau --blacklist svg,png,gif,ico,jpg,jpeg,bpm,mp3,mp4,ttf,woff,ttf2,woff2,eot,eot2,swf,swf2,css --fc 404 --threads #{$CONFIG['n_threads']} --verbose --proxy http://#{$CONFIG['proxy_addr']}:#{$CONFIG['proxy_port']}"
	end

	send_telegram_notif("Crawl-burp for #{params[:file]} finished")

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
		system "echo #{target}| gau --blacklist svg,png,gif,ico,jpg,jpeg,bpm,mp3,mp4,ttf,woff,ttf2,woff2,eot,eot2,swf,swf2,css --fc 404 --threads #{$CONFIG['n_threads']} --verbose --o output/#{target_sanitized}_gau.txt"
		adding_anew("output/#{target_sanitized}_gau.txt", "output/#{target_sanitized}_tmp.txt")

		if target_sanitized != target_tmp
			puts "\n[\e[34m*\e[0m] Finding more endpoints for #{target_sanitized} with ParamSpider\n"
			system "paramspider -d #{target_sanitized}"
		end
		target_tmp = target_sanitized
		adding_anew("results/#{target_sanitized}.txt", "output/#{target_sanitized}_tmp.txt")
		
		clean_urls "output/#{target_sanitized}_tmp.txt"
		adding_anew("output/#{target_sanitized}_tmp.txt","output/allUrls_#{file_sanitized}")
		puts "[\e[32m+\e[0m] Results for #{target} saved in output/allUrls_#{file_sanitized}"
	end

	system "rm -rf results/"

	# waymore
	remove_using_scope(file, "output/allUrls_#{file_sanitized}")
	extract_main_domains("output/allUrls_#{file_sanitized}", "output/_tmp_domains_#{file_sanitized}")
	File.open("output/_tmp_domains_#{file_sanitized}",'r').each_line do |f|
		target = f.strip
		puts "\n[\e[34m*\e[0m] Finding more endpoints for #{target} with WayMore\n"
		system "waymore -i #{target} -c /home/kali/.config/waymore/config.yml -f -p 5 -mode U -oU output/#{target}_waymore.txt"
		clean_urls "output/#{target}_waymore.txt"
		adding_anew("output/#{target}_waymore.txt","output/allUrls_#{file_sanitized}")
	end
	File.delete("output/_tmp_domains_#{file_sanitized}") if File.exists?("output/_tmp_domains_#{file_sanitized}")
	remove_using_scope(file, "output/allUrls_#{file_sanitized}")

	# JS file analysis
	puts "\n[\e[34m*\e[0m] Searching for JS files"
	system "cat output/allUrls_#{file_sanitized} | grep '\\.js$' | tee output/_tmpAllJSUrls_#{file_sanitized}"
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
	system "sed -E 's~^[a-zA-Z]+://([^:/]+).*~\\1~' output/allJSUrls_#{file_sanitized} | grep -v \"^*\\.\" | sed '/^\\s*$/d' | grep '\\.' | sort | uniq > output/tmp_scope.txt"
	system "xnLinkFinder -i output/allJSUrls_#{file_sanitized} -sf output/tmp_scope.txt -d 5 -p #{$CONFIG['n_threads']} -vv -insecure -sp #{file} -o output/xnLinkFinder_#{file_sanitized}"
	adding_anew("output/xnLinkFinder_#{file_sanitized}", "output/allUrls_#{file_sanitized}")
	remove_using_scope(file, "output/allUrls_#{file_sanitized}")
	File.delete("output/allJSUrls_#{file_sanitized}") if File.exists?("output/allJSUrls_#{file_sanitized}")
	
	# Find new URLS from Github using github-endpoints.py
	if !$CONFIG['github_token'].nil? || $CONFIG['github_token'] != "YOUR_GITHUB_TOKEN_HERE"
		puts "\n[\e[34m*\e[0m] Finding more endpoints with github-endpoints.py"
		File.open("output/tmp_scope.txt",'r').each_line do |f|
			target = f.strip
			system "python ~/Tools/web-attack/github-search/github-endpoints.py -d #{target} -t #{$CONFIG['github_token']} | tee output/github-endpoints_#{file_sanitized}"
			adding_anew("output/github-endpoints_#{file_sanitized}", "output/allUrls_#{file_sanitized}")
		end
		File.delete("output/tmp_scope.txt") if File.exists?("output/tmp_scope.txt")
	end

	# Final
	clean_urls "output/allUrls_#{file_sanitized}"
	File.delete("parameters.txt") if File.exists?("parameters.txt")
	puts "[\e[32m+\e[0m] Results for #{file} saved as output/allUrls_#{file_sanitized}"
	send_telegram_notif("Crawl-local for #{file} finished")

	# === SEARCH FOR VULNS ===
	if params[:vl_opt] == "y"
		params[:file] = "output/allUrls_#{file_sanitized}"
		params[:gb_opt] = "y"
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

		options_that_need_file = ["firefox", "get-to-burp", "assetenum", "webscreenshot", "crawl-burp", "crawl-local", "find-vulns", "find-vulns-base-url", "do-everything"]
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
rescue StandardError => e
	puts "\n[\e[31m+\e[0m] An error occurred: #{e.message}"
	puts e.backtrace
	send_telegram_notif 'easyg.rb crashed'
	exit 1
end
