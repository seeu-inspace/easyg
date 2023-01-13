File.open(ARGV[0],'r').each_line do |f|
	puts f if f.include?("https://") || f.include?("http://")
end