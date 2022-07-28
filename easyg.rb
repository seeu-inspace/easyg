require'socket'

puts "\e[35m\n E a s y G\n\e[0m"

def go_on(option, file_i)

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
			
			system option + target.to_s
			
			c += 1
			
			if c >= 30
				sleep 7
				c = 0
			end
			
		end
		
	end
	
end

if ARGV[0] == "firefox"
	option = "start firefox "
	file_i = ARGV[1]
	go_on(option, file_i)
end
		
if ARGV[0] == "dork"
	option = "start firefox www.google.com/search?q=site%3A"
	file_i = ARGV[1]
	go_on(option, file_i)
end
		
if ARGV[0] == "nmap"
	system "nmap -T4 -A -v -iL " + ARGV[1]
end

if ARGV[0] == "sublist3r"
	File.open(ARGV[1],'r').each_line do |f|
		begin
			target = f.gsub("\n","")
			print target + "\n"
		end
		system "python sublist3r.py -d" + target.to_s + " > " + target.to_s + ".txt"
		option = "start firefox "
		file_i = target.to_s + ".txt"
		go_on(option, file_i)
	end
end
