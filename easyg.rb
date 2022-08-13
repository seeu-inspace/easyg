# usage: ruby easyg.rb <file_input> <nmap/firefox/wayback/amass>
# if amass is selected, you can add firefox or wayback at the end
# for Linux, use "xdg-open" insead of "start firefox"

# Notes: (IGNORE)
# python waybackurls.py $scope include_subdomains
# result $scope-waybackurls.json

require 'socket'

puts "\e[35m\n E a s y G\n\e[0m"

$c = 0

def firefox(target)

	system "start firefox " + "http://" + target.to_s
	system "start firefox " + "https://" + target.to_s
			
	$c += 1
			
	if $c >= 15
		sleep 7
		$c = 0
	end

end

def go_on(file_i)

	File.open(file_i,'r').each_line do |f|
	
	begin
		ip=IPSocket::getaddress(f.strip)
		target = f.gsub("\n","")
		print target + "\n"
	rescue
		ip="unknown"
	end
			
		if ip!="unknown"
			
			firefox(target.to_s)
			
		end
		
	end
	
end

def wayback_go_on(file_i)

	File.open(file_i,'r').each_line do |f|
	
	begin
		target = f.gsub("\n","")
	end
			
		system "python waybackrobots.py " + target.to_s
			
		if File.exists?(target.to_s + ".my-robots.txt") == true
			
			File.open(target.to_s + ".my-robots.txt",'r').each_line do |f|
			begin
				target_robot = f.gsub("\n","")
			end
			
				firefox(target.to_s + target_robot.to_s)
				
			end

		end
			
	end
	
end

# --- OPTIONS ---

if ARGV[1] == "nmap"
	system "nmap -T4 -A -v -iL " + ARGV[0]
end

if ARGV[1] == "firefox"
	go_on(ARGV[0])
end

if ARGV[1] == "wayback"
	wayback_go_on(ARGV[0])
end

if ARGV[1] == "amass"

	File.open(ARGV[0],'r').each_line do |f|
	begin
		target = f.gsub("\n","")
	end
		
		system "amass enum -brute -active -d " + target.to_s + " -o " + target.to_s + ".txt"
		
		if ARGV[2] == "firefox"
			go_on(target.to_s + ".txt")
		end
		
		if ARGV[2] == "wayback"
			wayback_go_on(target.to_s + ".txt")
		end

	end
	
end
