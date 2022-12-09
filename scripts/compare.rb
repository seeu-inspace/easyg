#!/usr/bin/env ruby
File.open(ARGV[0],'r').each_line do |f2|
	File.open(ARGV[1],'r').each_line do |f1|
		puts f1 if f1.include? f2
	end
end