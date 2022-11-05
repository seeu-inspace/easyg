#!/usr/bin/env ruby
if File.directory?('output') == false
	system "mkdir output"
end

File.open(ARGV[0],'r').each_line do |f|

	target = f.gsub("\n","").to_s

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
	
	puts "\n[\e[34m+\e[0m] Adding the results for " + target + " to output/allsubs_gb_" + ARGV[0]
	system "type output\\" + target + "_gobuster.txt | anew output/allsubs_gb_" + ARGV[0]

end

puts "[\e[34m+\e[0m] Checking output/allsubs_gb_" + ARGV[0] + " with httprobe"
system "type output\\allsubs_gb_" + ARGV[0] + ".txt | httprobe -p http:81 -p http:3000 -p https:3000 -p http:3001 -p https:3001 -p http:8000 -p http:8080 -p https:8443 -c 150 > output/httprobed_gb_" + ARGV[0] + " && type output\\httprobed_" + ARGV[0]
