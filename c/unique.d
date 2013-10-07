import std.file : write, read, append;
import std.string;
import std.stdio : writeln;

void main(string[] args) {
	if (args.length == 3) {
		string file = args[1];
		string find = args[2];
		
		string value = cast(string)read(file);
		string findtext = cast(string)read(find);
		ptrdiff_t index;
		
		while((index = value.indexOf(findtext)) >= 0) {
			writeln(file,":",find,":",index);
			
			if (index >= 0) {
				if (index + 1 + findtext.length < value.length) {
					if (index == 0) {
						value = value[findtext.length + 1 .. $];
					} else {
						value = value[0 .. index] ~ value[index + 1 + findtext.length .. $];
					}
				} else {
					value = value[0 .. index];
				}
			}
		}
		write(file, value ~ "\n" ~ findtext ~ "\n");
	}
}