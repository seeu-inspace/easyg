# Fare opzione sublist3r + firefox

require'socket'

puts "\e[35m\n E a s y G\n\e[0m"
		
option = "inurl:& ext:jsp OR ext:asp OR ext:aspx OR ext:php OR ext:do OR ext:php3"

c = 0

File.open(ARGV[0],'r').each_line do |f|
	begin
		target = f.gsub("\n","")
	rescue
	end
	
	if c == 0
		option += " site:" + target.to_s
	end
	
	if c > 0
		option += " OR site:" + target.to_s
	end
	
	c += 1
	
	if c >= 20
		puts option + "\n\n"
		option = "inurl:& ext:jsp OR ext:asp OR ext:aspx OR ext:php OR ext:do OR ext:php3"
		c = 0
	end
	
end