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
system "nuclei -l output/httprobe_" + ARGV[0] + " -t %USERPROFILE%/nuclei-templates/takeovers -t %USERPROFILE%/nuclei-templates/exposures/configs/git-config.yaml -t %USERPROFILE%/nuclei-templates/vulnerabilities/generic/crlf-injection.yaml -t %USERPROFILE%/nuclei-templates/exposures/apis/swagger-api.yaml -t %USERPROFILE%/nuclei-templates/exposed-panels -t %USERPROFILE%/nuclei-templates/miscellaneous/old-copyright.yaml -stats -o output/nuclei_" + ARGV[0]
delete_if_empty "output/nuclei_" + ARGV[0]

#== check for log4j with Nuclei ==
puts "[\e[36m+\e[0m] Checking for log4j in " + ARGV[0] + " with Nuclei"
system "nuclei -l output/httprobe_" + ARGV[0] + " -as -tags log4j -stats -o output/nuclei_log4j_" + ARGV[0]
delete_if_empty "output/nuclei_log4j_" + ARGV[0]

#== check for CVEs with Nuclei ==
puts "[\e[36m+\e[0m] Checking for CVEs in " + ARGV[0] + " with Nuclei"
system "nuclei -l output/httprobe_" + ARGV[0] + " -as -tags cve -stats -o output/nuclei_cves_" + ARGV[0]
delete_if_empty "output/nuclei_cves_" + ARGV[0]