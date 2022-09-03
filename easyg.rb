# https://github.com/seeu-inspace/easyg/blob/main/easyg.rb

require 'net/http'
require 'json'

puts "\e[35m\n E a s y G\n\e[0m"

$c = 0

def firefox_go_on(file_i)

	File.open(file_i,'r').each_line do |f|
	begin
		target = f.gsub("\n","")
	end
		system 'start firefox "' + target.to_s + '"'
		puts target.to_s
		
		$c += 1
				
		if $c >= 15
			sleep 30
			$c = 0
		end
	end

end

def httprobe_go_on(file_i)

	system "type " + file_i + " | httprobe -p http:81 -p http:3000 -p https:3000 -p http:3001 -p https:3001 -p http:8000 -p http:8080 -p https:8443 -c 50 > " + file_i +  "_httprobed"
	
end

def gau_go_on(file_i)

	system "type " + file_i + " | httprobe -p http:81 -p http:3000 -p https:3000 -p http:3001 -p https:3001 -p http:8000 -p http:8080 -p https:8443 -c 50 | gau --o " + file_i + "_gau.txt --blacklist svg,png,gif,ico,jpg,bpm,mp3,mp4,ttf,woff,ttf2,woff2,eot,eot2,pptx,pdf,epub,docx,xlsx,css,txt --mc 200"

end

# --- OPTIONS ---

if ARGV[1] == "nmap"
	system "nmap -p 1-65535 -T4 -A -v -Pn -iL " + ARGV[0] + " -oX " + ARGV[0] +  ".xml"
end

if ARGV[1] == "firefox"
	firefox_go_on(ARGV[0])
end

if ARGV[1] == "firefox-httprobe"
	firefox_go_on(ARGV[0])
	httprobe_go_on(ARGV[0] + "_httprobed")
end

if ARGV[1] == "gau"
	gau_go_on(ARGV[0])
end

if ARGV[1] == "amass"

	File.open(ARGV[0],'r').each_line do |f|
	begin
		target = f.gsub("\n","")
	end
		
		system "amass enum -brute -active -d " + target.to_s + " -o " + target.to_s + ".txt"
		
		httprobe_go_on(target.to_s + ".txt")

	end
	
end

if ARGV[0] == "help"

	puts 'Usage: ruby easyg.rb <file_input> <option>'+ "\n\n"
	puts 'options:'
	puts ' nmap				perform nmap scan against the domains in the <file_input>'
	puts ' firefox			open the strings in the <file_input> in firefox'
	puts ' firefox-httprobe		open the strings in the <file_input> in firefox checking them first with httprobe'
	puts ' gau				perform gau scan against the strings in the <file_input>'
	puts ' amass				subdomain discovery'+ "\n\n"
	
	puts 'Notes:'
	puts ' - tested on Windows, if you need to use it on Unix:'
	puts '   > use `xdg-open` insead of `start firefox`'
	puts '   > Use `cat` instead of type'
	
end
