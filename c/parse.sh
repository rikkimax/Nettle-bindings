rm -rf ../source/static/nettle/*.d
rm -rf ../source/dynamic/nettle/*.d

echo "" > output/all.defs
echo "" > output/all.impl
echo "" > output/all.types
echo "" > output/all.bind
for file in files/*.c
do
	file=$(basename "$file")
	file="${file%.*}"
	
	echo "typedef struct{} __mpz_struct;" > output/$file.h
	echo "typedef __mpz_struct mpz_t[1];" >> output/$file.h
	
	gcc files/$file.c -I. -E -P -lgmp -nostdinc >> output/$file.h

	echo "Creating bindings for header nettle/$file.h"

	cp output/$file.h .temp
	cat .temp |
	grep -v "#pragma.*" |
	grep -v "__dllimport__" |
	grep -v "__gnuc" |
	grep -v "vector_size__" |
	grep -v "__asm__" |
	grep -v "__m128" |
	grep -v "struct [a-zA-Z0-9_]*;" > output/$file.h

	sed -i 's/__extension__//g' output/$file.h
	sed -i 's/__inline__//g' output/$file.h
	sed -i 's/__inline//g' output/$file.h
	sed -i 's/__volatile__//g' output/$file.h
	sed -i 's/__restrict__//g' output/$file.h
	sed -i 's/__attribute__[ ]*((__aligned__[ ]*(16)))//g' output/$file.h
	sed -i 's/__attribute__[ ]*\([(__cdecl__)(__always_inline__)(__artificial__)(__gnu_inline__)(__returns_twice__)(__nothrow__)(__dllimport__),]*\)//g' output/$file.h
	
	./htod output/$file.h output/$file.d -hc

	sed -i 's/C func(/function(/g' output/$file.d
	sed -i 's/ in)/)/g' output/$file.d
	sed -i 's/alias ubyte byte;//g' output/$file.d
	sed -i "s/module output\/$file;/module nettle.$file;/g" output/$file.d
	
	echo "struct nettle_buffer;" >> output/$file.d
	echo "struct sexp_iterator;" >> output/$file.d
	echo "struct asn1_der_iterator;" >> output/$file.d
	
	cp output/$file.d .temp
	cat .temp |
	grep -v "alias uint ulong;" > output/$file.d
	
	cat output/$file.d | awk '
!/^[ ]*[a-zA-Z_][a-zA-Z_0-9]*[ ]*[a-zA-Z_][a-zA-Z_0-9]*[ ]*\([ ]*([a-zA-Z_][a-zA-Z_0-9]*[ ]*\*?[ ]*[a-zA-Z_][a-zA-Z_0-9]*)[ ]*(,[ ]*[a-zA-Z_][a-zA-Z_0-9]*[ ]*\*?[ ]*[a-zA-Z_][a-zA-Z_0-9]*)*\);[ ]*$/
' |
	grep -v "^module" |
	grep -v "^/\*.*\*/$" | 
	grep -v "^extern[ ]*\(.*\):" |
	tr '\n' '\t' |
	awk '
{
gsub(/struct[ ]*[a-zA-Z0-9_]*[ \t]*\{[ \t]*\}\t/, "");
print;
}
' |
	tr '\t' '\n' |
	grep -v "^struct.*;$" |
	grep -v "__mpz_struct" |
	grep -v "alias ubyte uint8_t;" |
	grep -v "alias uint uint32_t;" |
	grep -v "alias ulong uint64_t;" >> output/all.types
	
	gcc files/$file.c -E -P -dD  -I. -lgmp -nostdinc -undef > output/$file.h.vars
	cp output/$file.h.vars .temp
	cat .temp | awk '
function rindex(str,c) {
  return match(str,"\\" c "[^" c "]*$")? RSTART : 0
}
function ltrim(v) { 
   gsub(/^[ \t]+/, "", v); 
   return v; 
} 
function rtrim(v) { 
   gsub(/[ \t]+$/, "", v); 
   return v; 
} 
function trim(v) { 
   return ltrim(rtrim(v)); 
} 

/^.*#define [a-zA-Z0-9_]+ +-?[xA-F><0-9]+$/{
$line = substr($0, index($0, "#define"));
$n = split($line, vals, " ");
val="";
for(i=3;i<=$n;i++)
	val=val" "vals[i];
if (val != "" && index(vals[2], "(") == 0)
	print "const", vals[2], "="val";";
for(i in vals)
	delete vals[i];
};

/^.* [A-Za-z_0-9]+ *\( *-?[xA-F><0-9]+ *\)$/{
line = substr($0, index($0, "#define"));
n = split(line, vals, " ");
start = rindex(line, "(") + 1;
end = index($line, ")") - start
val = substr(line, start, end);
if (val != "" && index(vals[2], "(") == 0)
	print "const",vals[2],"=",val";";
};

/^.*#define [a-zA-Z0-9_]+ *\(int\) *-?[xA-F><0-9]+$/{
$line = substr($0, index($0, "#define"));
$n = split($line, vals, " ");
val="";
for(i=3;i<=$n;i++)
	val=val" "vals[i];
if (val != "" && index(vals[2], "(") == 0)
	print "const", vals[2], "=" substr(val, 7)";";
for(i in vals)
	delete vals[i];
};

/^ *#define [A-Za-z_0-9]+ *\( *\(int\) *-?[xA-F><0-9]+ *\)$/{
line = substr($0, index($0, "#define"));
n = split(line, vals, " ");
start = rindex(line, "(") + 5;
end = rindex(line, ")") - start
val = substr(line, start, end);
if (val != "")
	print "const",vals[2],"=",val";";
};

/^.*#define [a-zA-Z0-9_]+ [xA-F><0-9]+L$/{
$line = substr($0, index($0, "#define"));
$n = split($line, vals, " ");
val="";
for(i=3;i<=$n;i++)
	val=val" "vals[i];
if (val != "" && index(vals[2], "(") == 0)
	print "const", vals[2], "="substr(val, 0, length(val)-1)";";
for(i in vals)
	delete vals[i];
};

/^.* [A-Za-z_0-9]+\([xA-F><0-9]+L\)$/{
line = substr($0, index($0, "#define"));
n = split(line, vals, " ");
start = rindex(line, "(") + 1;
end = index($line, ")") - start
val = substr(line, start, end);
if (val != "" && index(vals[2], "(") == 0)
	print "const",vals[2],"=",substr(val, 0, length(val)-1)";";
};

/^.*#define [a-zA-Z0-9_]+ L?".*"$/{
$line = substr($0, index($0, "#define"));
$n = split($line, vals, " ");
val="";
for(i=3;i<=$n;i++)
	val=val" "vals[i];
val = trim(val);
if (match(val, "^L.*") > 0)
	val = substr(val, 2);
if (val != "" && index(vals[2], "(") == 0)
	print "const", vals[2], "=", val";";
for(i in vals)
	delete vals[i];
};

/^.*#define [a-zA-Z0-9_]+ [a-zA-Z_]+[A-Z][a-zA-Z_0-9+]$/{
$line = substr($0, index($0, "#define"));
$n = split($line, vals, " ");
val="";
for(i=3;i<=$n;i++)
	val=val" "vals[i];
val = trim(val);
if (val != "" && index(vals[2], "(") == 0)
	print "static if (__traits(compiles, typeof("val"))) static if (!__traits(isStaticFunction, "val")) static if (__traits(isPOD, typeof("val")))","const", vals[2], "=", val";";
for(i in vals)
	delete vals[i];
};

/^ *#define [a-zA-Z][a-zA-Z_0-9]*  *\( *([a-zA-Z][a-zA-Z_0-9]*( *\| *)*)+\)$/{
$line = substr($0, index($0, "#define"));
$n = split($line, vals, " ");
val="";
for(i=3;i<=$n;i++)
	val=val" "vals[i];
val = trim(val);
if (val != "" && index(vals[2], "(") == 0)
	print "static if (__traits(compiles, typeof("val"))) static if (!__traits(isStaticFunction, "val")) static if (__traits(isPOD, typeof("val")))","const", vals[2], "=", val";";
for(i in vals)
	delete vals[i];
};' |
	grep -v "__VERSION__" |
	grep -v "__STDC" |
	grep -v "_STDINT_H" >> output/$file.d
	
	rm .temp
	rm output/$file.h
	rm output/$file.h.vars

	cp output/$file.d ../source/static/nettle/
	
	cat output/$file.d | awk '
function ltrim(v) { 
   gsub(/^[ \t]+/, "", v); 
   return v; 
} 
function rtrim(v) { 
   gsub(/[ \t]+$/, "", v); 
   return v; 
} 
function trim(v) { 
   return ltrim(rtrim(v)); 
} 

/^[ ]*[a-zA-Z_][a-zA-Z_0-9]*[ ]*[a-zA-Z_][a-zA-Z_0-9]*[ ]*\([ ]*([a-zA-Z_][a-zA-Z_0-9]*[ ]*\*?[ ]*[a-zA-Z_][a-zA-Z_0-9]*)[ ]*(,[ ]*[a-zA-Z_][a-zA-Z_0-9]*[ ]*\*?[ ]*[a-zA-Z_][a-zA-Z_0-9]*)*\);[ ]*$/{
$line = $0;
if (index($line, " (") == 0)
	sub(/\(/, " (", $line);
if (substr($line, length($line)) == ";")
	$line = substr($line, 1, length($line) - 1);
$n = split($line, vals, " ");
val="";
for(i=3;i<=$n;i++)
	val=val" "vals[i];
val = trim(val);
print "alias "vals[1]" function"val" da_"vals[2]";";
for(i in vals)
	delete vals[i];
};' >> output/all.defs

	cat output/$file.d | awk '
function ltrim(v) { 
   gsub(/^[ \t]+/, "", v); 
   return v; 
} 
function rtrim(v) { 
   gsub(/[ \t]+$/, "", v); 
   return v; 
} 
function trim(v) { 
   return ltrim(rtrim(v)); 
} 

/^[ ]*[a-zA-Z_][a-zA-Z_0-9]*[ ]*[a-zA-Z_][a-zA-Z_0-9]*[ ]*\([ ]*([a-zA-Z_][a-zA-Z_0-9]*[ ]*\*?[ ]*[a-zA-Z_][a-zA-Z_0-9]*)[ ]*(,[ ]*[a-zA-Z_][a-zA-Z_0-9]*[ ]*\*?[ ]*[a-zA-Z_][a-zA-Z_0-9]*)*\);[ ]*$/{
$line = $0;
if (index($line, " (") == 0)
	sub(/\(/, " (", $line);
if (substr($line, length($line)) == ";")
	$line = substr($line, 1, length($line) - 1);
$n = split($line, vals, " ");
print "bindFunc(cast(void**)&"vals[2]", \""vals[2]"\");";
for(i in vals)
	delete vals[i];
};' >> output/all.bind

	cat output/$file.d | awk '
function ltrim(v) { 
   gsub(/^[ \t]+/, "", v); 
   return v; 
} 
function rtrim(v) { 
   gsub(/[ \t]+$/, "", v); 
   return v; 
} 
function trim(v) { 
   return ltrim(rtrim(v)); 
} 

/^[ ]*[a-zA-Z_][a-zA-Z_0-9]*[ ]*[a-zA-Z_][a-zA-Z_0-9]*[ ]*\([ ]*([a-zA-Z_][a-zA-Z_0-9]*[ ]*\*?[ ]*[a-zA-Z_][a-zA-Z_0-9]*)[ ]*(,[ ]*[a-zA-Z_][a-zA-Z_0-9]*[ ]*\*?[ ]*[a-zA-Z_][a-zA-Z_0-9]*)*\);[ ]*$/{
$line = $0;
if (index($line, " (") == 0)
	sub(/\(/, " (", $line);
if (substr($line, length($line)) == ";")
	$line = substr($line, 1, length($line) - 1);
$n = split($line, vals, " ");
val="";
for(i=3;i<=$n;i++)
	val=val" "vals[i];
val = trim(val);
print "da_"vals[2]" "vals[2]";";
for(i in vals)
	delete vals[i];
};' >> output/all.impl

	echo "void main(){}" >> output/$file.d
	rdmd output/$file.d
done

for file in files/remove/*.d
do
	rdmd remove.d output/all.types $file
done


cat files/dynamic/functions.top > ../source/dynamic/nettle/functions.d
cat output/all.defs | awk '{print "    "$0;}' | sort - -u >> ../source/dynamic/nettle/functions.d
cat files/dynamic/functions.middle >> ../source/dynamic/nettle/functions.d
cat output/all.impl | awk '{print "    "$0;}' | sort - -u >> ../source/dynamic/nettle/functions.d
cat files/dynamic/functions.bottom >> ../source/dynamic/nettle/functions.d

cat files/dynamic/types.top > ../source/dynamic/nettle/types.d
cat output/all.types >> ../source/dynamic/nettle/types.d

cat files/dynamic/nettle.top > ../source/dynamic/nettle/nettle.d
cat output/all.bind | awk '{print "            "$0;}' | sort - -u >> ../source/dynamic/nettle/nettle.d
cat files/dynamic/nettle.bottom >> ../source/dynamic/nettle/nettle.d
