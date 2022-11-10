<%
Dim Vars
%>
<TABLE width="75%" BORDER=1 align="center" cellpadding="3" cellspacing="0">
	<% For Each Vars In Request.ServerVariables %>
	<TR>
		<TD><%= Vars %></TD>
		<TD><%= Request.ServerVariables(Vars) %>&nbsp;</TD>
	</TR>
	<% Next %>
</TABLE>