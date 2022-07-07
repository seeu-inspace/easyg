#nmap -p 1-65535 -T4 -A -v

require'socket'

puts "\e[35m\n E a s y G\n\e[0m"

c = 0

File.open(ARGV[1],'r').each_line do |f|
	begin
		ip=IPSocket::getaddress(f.strip)
		target = f.gsub("\n","")
		print target + "\n"
	rescue
		ip="unknown"
	end
		
	if ip!="unknown"
		if ARGV[0] == "firefox"
			system "start firefox " + target.to_s
		end
		
		if ARGV[0] == "dork"
			system "start firefox www.google.com/search?q=site%3A" + target.to_s
		end
		
		if ARGV[0] == "nmap"
			system "nmap " + target.to_s
		end
		
		c += 1
		
		if c >= 30
			sleep 7
			c = 0
		end
		
	end
end
