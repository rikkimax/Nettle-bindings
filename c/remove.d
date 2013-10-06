import std.file : write, read;
import std.string;
import std.stdio : writeln;

void main(string[] args) {
	if (args.length == 3) {
		string file = args[1];
		string find = args[2];
		
		string filetext = cast(string)read(file);
		string findtext = cast(string)read(find);
		
		string value;
		auto index = filetext.indexOf(findtext);
		
		writeln(file,":",find,":",index);
		
		if (index >= 0) {
			if (index + 1 + findtext.length < filetext.length) {
				if (index == 0) {
					value = filetext[findtext.length + 1 .. $];
				} else {
					value = filetext[0 .. index] ~ filetext[index + 1 + findtext.length .. $];
				}
			} else {
				value = filetext[0 .. index];
			}
			write(file, value);
		}
	}
}