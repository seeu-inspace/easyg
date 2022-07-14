# EasyG

### About EasyG

EasyG is a script to automate some tasks for information gathering for PenTesting and Bug Hunting

### Usage

- To open all the URLs listed in a text file with the FireFox browser:
  ```
  ruby easyg.rb firefox <FILENAME>
  ```
- To search on Google `site:TARGET` for every line of a text file: 
  ```
  ruby easyg.rb dork <FILENAME>
  ```
  
- To scan a list of targets with nmap from a text file: 
  ```
  ruby easyg.rb nmap <FILENAME>
  ```
