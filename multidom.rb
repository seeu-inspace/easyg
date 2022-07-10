## Fare opzione sublist3r + firefox

require'socket'

puts "\e[35m\n MultiDom\n\e[0m"

c = 0

File.open(ARGV[0],'r').each_line do |f|
	begin
		target = f.gsub("\n","")
		print target + "\n"
	rescue
	
	end
	
	system "python sublist3r.py -d " + target.to_s + " > out" + c.to_s + ".txt"
	
	c += 1
	
end