#!/usr/bin/env ruby
File.open(ARGV[0],'r').each_line do |f|
	
	target = f.gsub("\n","").to_s
	
	puts "[\e[34m+\e[0m] Crawling " + target + " with hakrawler" + "\n"
	system 'echo ' + target + '| hakrawler -u -insecure -t 20 -proxy http://localhost:8080 -h "Cookie: 0=1"'
	
	puts "[\e[34m+\e[0m] Crawling " + target + " with gospider" + "\n"
	system 'gospider -s "' + target + '" -c 10 -d 4 -t 20 --sitemap --other-source -p http://localhost:8080 --cookie "0=1" --blacklist ".(svg|png|gif|ico|jpg|jpeg|bpm|mp3|mp4|ttf|woff|ttf2|woff2|eot|eot2|swf|swf2|css)"'
	
	puts "[\e[34m+\e[0m] Crawling " + target + " with katana" + "\n"
	system 'katana -u "' + target + '" -jc -kf -aff -proxy http://127.0.0.1:8080" -H "Cookie: 0=1"'
	
end
