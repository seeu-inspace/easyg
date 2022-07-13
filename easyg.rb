# Fare opzione sublist3r + firefox

require'socket'

puts "\e[35m\n E a s y G\n\e[0m"

if ARGV[0] == "firefox"
	option = "start firefox "
end
		
if ARGV[0] == "dork"
	option = "start firefox www.google.com/search?q=site%3A"
end
		
if ARGV[0] == "nmap"
	option = "nmap -Pn "
end

if ARGV[0] == "nmap-int"
	option = "nmap -p 1-65535 -T4 -A -v "
end

if option != nil

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
		
			system option + target.to_s
			
			c += 1
			
			if c >= 30
				sleep 7
				c = 0
			end
			
		end
		
	end
	
end
