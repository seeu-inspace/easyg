require'socket'

puts "\e[35m\n E a s y G\n\e[0m"

def go_on(file_i)

	c = 0

	File.open(file_i,'r').each_line do |f|
	
		begin
			ip=IPSocket::getaddress(f.strip)
			target = f.gsub("\n","")
			print target + "\n"
		rescue
			ip="unknown"
		end
			
		if ip!="unknown"
			
			system "start firefox " + "http://" + target.to_s
			system "start firefox " + "https://" + target.to_s
			
			c += 1
			
			if c >= 15
				sleep 7
				c = 0
			end
			
		end
		
	end
	
end

if ARGV[0] == "nmap"
	system "nmap -T4 -A -v -iL " + ARGV[1]
end

if ARGV[0] == "firefox"
	go_on(ARGV[1])
end

if ARGV[0] == "amass"

	File.open(ARGV[1],'r').each_line do |f|
		begin
			target = f.gsub("\n","")
		end
		
		system "amass enum -brute -active -d " + target.to_s + " -o " + target.to_s + ".txt"
		go_on(target.to_s + ".txt")
		
	end
	
end
