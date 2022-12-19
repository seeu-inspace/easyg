#!/usr/bin/env ruby
def delete_if_empty(file)

	if File.zero?(file)
		puts "[\e[36m+\e[0m] No result found"
		File.delete(file) if File.exists?(file)
	else
		puts "[\e[36m+\e[0m] Results added at " + file
	end
	
end

system "mkdir output" if File.directory?('output') == false

#== nuclei ==	
puts "[\e[36m+\e[0m] Checking with nuclei in " + ARGV[0]
system "nuclei -l " + ARGV[0] + " -t %USERPROFILE%/nuclei-templates/takeovers -t %USERPROFILE%/nuclei-templates/exposures/configs/git-config.yaml -t %USERPROFILE%/nuclei-templates/vulnerabilities/generic/crlf-injection.yaml -t %USERPROFILE%/nuclei-templates/exposures/apis/swagger-api.yaml -t %USERPROFILE%/nuclei-templates/exposed-panels -t %USERPROFILE%/nuclei-templates/miscellaneous/old-copyright.yaml -stats -o output/nuclei_" + ARGV[0]
delete_if_empty ARGV[0]

#== check for log4j and cve with Nuclei ==
puts "[\e[36m+\e[0m] Checking for log4j in " + ARGV[0] + " with nuclei"
system "nuclei -l " + ARGV[0] + " -as -tags log4j,cve -stats -o output/nuclei_2_" + ARGV[0]
delete_if_empty ARGV[0]
