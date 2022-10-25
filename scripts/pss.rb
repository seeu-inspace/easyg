#!/usr/bin/env ruby
File.open(ARGV[0],'r').each_line do |f|
	target = f.gsub("\n","").to_s
	system "python paramspider.py --domain " + target + " --exclude svg,png,gif,ico,jpg,jpeg,bpm,mp3,mp4,ttf,woff,ttf2,woff2,eot,eot2,swf,swf2,pptx,pdf,epub,docx,xlsx,css,txt,js,axd --level high --subs False --output output/" + target + ".txt"
	if File.exists? "output/" + target.to_s + ".txt"
		system "type output\\" + target + ".txt | trashcompactor | anew output/" + ARGV[0].gsub('.txt','') + "_pss.txt"
		File.delete("output/" + target.to_s + ".txt")
	end
end
