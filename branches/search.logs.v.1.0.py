#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os, sys, re, codecs
import argparse
import sqlite3
import unicodedata

import graphviz as gv
import functools

import networkx as nx
import matplotlib.pyplot as plt
import pygraphviz

dateType = {
    1: '\d{4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}\.\d+Z',
    2: '\d{4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}\.\d+|-\d{1,2}:\d+',
    3: '\d{4}-\d{1,2}-\d{1,2} \d{1,2}:\d{1,2}:\d{1,2}\.\d+',
    4: '\d{4}-\d{1,2}-\d{1,2} \d{1,2}-\d{1,2}-\d{1,2}',
    5: '\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{1,2}:\d{1,2}\.\d+',
    6: '\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{1,2}:\d{1,2}',
    7: 'Ene|Feb|Mar|Abr|May|Jun|Jul|Ago|Sep|Oct|Nov|Dic \d{1,2} \d{1,2}:\d{1,2}:\d{1,2}',
    8: '\d{4}-\d{1,2}-\d{1,2} \d{1,2}:\d{1,2}:\d{1,2},\d{3}',
    9: '\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{1,2}:\d{1,2}\.\d+'
}

parser = argparse.ArgumentParser(
    description ='Process some file.',
    epilog      = 'comments > /dev/null'
)

parser.add_argument('--filename',  "-f", type=str, help='a filename to parse')
parser.add_argument('--directory', "-d", type=str, help='a route to check date format')
parser.add_argument('--delimiter', "-del", type=str, help='a delimiter for the line', default=" ")
parser.add_argument('--datetype', "-dt", action='store_true', help='To check timestamp format')
parser.add_argument('--multi', '-m' ,action='store_true',help='if you want only display multiline entries found')
parser.add_argument('--single', '-s' ,action='store_true',help='if you want only display single line entries found')
parser.add_argument('--substr', "-r", type=str, help='a string to find')
parser.add_argument('--threat', "-t", action='store_true', help='a threat to find')
parser.add_argument('--user', "-u", action='store_true', help='a user id pattern to find')
parser.add_argument('--PAN', "-p", action='store_true', help='a PAN pattern to find')
parser.add_argument('--email', "-e", action='store_true', help='an email pattern to find')
parser.add_argument('--ipv4', "-i", action='store_true', help='an ip v4 address pattern to find')
parser.add_argument('--BAN', "-b", action='store_true', help='a Bank Account Number pattern to find')
parser.add_argument('--create', "-c", action='store_true', help='To create a database')
parser.add_argument('--graph', "-g", action='store_true', help='Testing something')
parser.add_argument('--central', "-l", action='store_true', help='Something about centrality')
parser.add_argument('--graphviz', "-vg", action='store_true', help='a graphviz output')
parser.add_argument('--verbose', "-v", action='store_true', help='a graphviz output')
parser.add_argument('--GraphNormalize', "-gn",  action='store_true', help='To clean')
parser.add_argument('--jumpNode', "-j",  type=str, help='To see a branch')
parser.add_argument('--KnowMN', "-k",  action='store_true', help='To know the minNumber')
parser.add_argument('--ShowGrammar', "-sg",  action='store_true', help='Show the paths')



args = parser.parse_args()
minNode = 8;
DATE = ""
count = 0
linea = ""
DATABASE = "graph.db"

#-----------------------------------------------------------------------
def date_identificator(line):
    flag = False
    resultado = -1
    for id in dateType:
        resultado = re.search(dateType[id], line)
        if resultado:
            return re.sub(dateType[id], str(id), line)
    return "mac"+line
#-----------------------------------------------------------------------
def strip_string(line):
    flag = False
    resultado = -1
    for id in dateType:
        resultado = re.search("WebContainer : \d+" , line)
        if resultado:
            return re.sub(r'(WebContainer) : (\d+)', r'\1:\2', line)
    return line
#-----------------------------------------------------------------------
def mgmtFILE(file):
    format_date=set([])
    for line in codecs.open(file, 'r', encoding='ISO-8859-1'):
        line = date_identificator(line)
        line = strip_string(line)
        #line = re.sub('\s+', " ", line).strip()
        if (line.split(args.delimiter, minNode)[0]).isdigit():
            format_date.add(int(line.split(args.delimiter, minNode)[0]))
        if args.single or args.multi:
            if (line.split(args.delimiter, minNode)[0]).isdigit():
                sacar()
            line = re.sub('^mac', " ", line).strip()
            meter( line )
    if args.datetype:
        print "[%s]" % args.datetype
        for date in format_date:
            print date," ",dateType[date],"\n"

    if args.single or args.multi:
        sacar()
#-----------------------------------------------------------------------
def elimina_tildes(s):
   return ''.join((c for c in unicodedata.normalize('NFD', s) if unicodedata.category(c) != 'Mn'))
#-----------------------------------------------------------------------

def meter(cadena):
    global linea
    global count
    linea += cadena
    count += 1
#-----------------------------------------------------------------------
def sacar():
    global linea
    global count
    if ( count > 1 and args.multi):
        if ( args.threat or args.ipv4 or args.email or
               args.user or args.PAN or args.BAN):
            suspicious ( linea )
        else:
            print chomps(linea)
    elif ( count == 1 and args.single):
        if args.substr :
            if args.substr.lower() in linea.lower() :
                print chomps(linea)
        elif ( args.threat or args.ipv4 or args.email or
               args.user or args.PAN or args.BAN):
            suspicious ( linea )
        else:
            print chomps(linea)

    linea   = ''
    count = 0
#-----------------------------------------------------------------------
def chomps(s):
    return s.rstrip('\n')
#-----------------------------------------------------------------------
def showContents (file):
    for line in open (args.filename,'r'):
        if ( re.search ( "^\d{1,2}\/\d{1,2}\/\d{4} \d{2}:\d{2}:\d{2}", line)):
            sacar()
        meter( line )
    sacar()
#-----------------------------------------------------------------------
def suspicious(cadena):

    flag = False
    if  ( args.threat or args.ipv4 ) :
        resultado = re.findall( "(\d{1,3}\.\d{1,3}\.\d{1,4}\.\d{1,3})", cadena)
    if resultado :
        print
        print "IPV4 info found !!!"
        for n in resultado:
            print n
        flag = True

    if ( args.threat or args.email ) :
        resultado = re.findall ( "([\w|\-]*\w+@[\w|\-]*\.\w+)", cadena)
    if resultado :
        print
        print "email info found !!!"
        for n in resultado:
            print n
        flag = True

    if ( args.threat or args.user ) :
        resultado = re.findall ( "\s(([a-zA-Z]{1}\d{6}|[a-zA-Z]{2}\d{5}))\s", cadena)
    if resultado :
        print
        print "UserID info found !!!"
        for n in resultado:
            print n
            flag = True

    if ( args.threat or args.PAN ):
        resultado = re.findall ( "\s(\d{16}|\d{4}[\s|\-|\.]\d{4}[\s|\-|\.]\d{4}[\s|\-|\.]\d{4})\s", cadena)
    if resultado :
        print
        print "PAN info found !!!"
        for n in resultado:
            print n
            flag = True

    if ( args.threat or args.PAN ):
        resultado = re.findall ( "\s(\d{1,2}\/ls\d{1,2})\s", cadena)
    if resultado :
        print
        print "PAN info found !!!"
        for n in resultado:
            print n
            flag = True

    if ( args.threat or args.BAN ):
        resultado = re.findall ( "\s([a-zA-Z]{2}\d{22}|\d{20})\s", cadena )
                  #or
    if resultado:
        print
        print "1 BAN info found !!!"
        for n in resultado:
            print n
            flag = True
    resultado = re.findall ( "\s((?:[a-zA-Z]{2}\d{2}[\s|\-|\.])?\d{4}[\s|\-|\.]\d{4}[\s|\-|\.]\d{4}[\s|\-|\.]\d{4}[\s|\-|\.]\d{4})\s", cadena)
    if resultado:
        print
        print "2 BAN info found !!!"
        for n in resultado:
            print n
            flag = True
    if flag:
        print "[Original line]"
        print chomps ( cadena )
#-----------------------------------------------------------------------
############ DATABASE
#-----------------------------------------------------------------------
def openDataBase (database):
    if not ( os.path.exists(database))	:
        print ( "database %s does not exists or is not accesible".format( database ))
    conn = sqlite3.connect(database, isolation_level=None)
    conn.text_factory = lambda x: unicode(x, "utf-8", "ignore")
    return conn

def create_all_databases(DATABASE):
    conn = openDataBase(DATABASE)
    c = conn.cursor()
    try:
        c.execute('''CREATE TABLE c_NODE
                (literal text, id_Node INTEGER PRIMARY KEY AUTOINCREMENT
                , hits integer, in_hits integer, out_hits integer
                , in_num integer, out_num integer, deep integer, Original boolean)''')
        c.execute('''CREATE INDEX i_NODE on c_NODE
                (literal, id_Node)''')
    except:
        print ( "Managed error :[1.1]:", sys.exc_info()[1] )
        c.execute('''DROP TABLE c_NODE''')
        c.execute('''CREATE TABLE c_NODE
                (literal text, id_Node INTEGER PRIMARY KEY AUTOINCREMENT
                , hits integer, in_hits integer, out_hits integer
                , in_num integer, out_num integer, deep integer, Original boolean)''')
        c.execute('''CREATE INDEX id_NODE on c_NODE
                (literal, id_Node)''')


    try:
        c.execute('''CREATE TABLE t_GRAPH
                (source integer, destination integer, hits integer)''')
        c.execute('''CREATE INDEX t_GRAPH on t_GRAPH
                (source, destination)''')
    except:
        print ( "Managed error :[2.1]:", sys.exc_info()[1] )
        c.execute('''DROP TABLE t_GRAPH''')
        c.execute('''CREATE TABLE t_GRAPH
                (source integer, destination integer, hits integer)''')
        c.execute('''CREATE INDEX i_GRAPH on t_GRAPH
                (source, destination)''')
    try:
        c.execute('''CREATE TABLE t_CHANGES
                (id_Change INTEGER PRIMARY KEY AUTOINCREMENT, id_changed integer, id_original integer)''')
    except:
        print ( "Managed error :[3.1]:", sys.exc_info()[1] )
        c.execute('''DROP TABLE t_CHANGES''')
        c.execute('''CREATE TABLE t_CHANGES
                (id_Change INTEGER PRIMARY KEY AUTOINCREMENT, id_changed integer, id_original integer)''')
#-----------------------------------------------------------------------
def centrality (DATABASE):
    search_all_nodes = "SELECT id_Node FROM c_NODE ORDER BY 1 ASC"
    select_num_sources = "SELECT SUM(hits), COUNT(hits) FROM t_GRAPH WHERE source = '%s'"
    select_num_destinations = "SELECT SUM(hits), COUNT(hits) FROM t_GRAPH WHERE destination = '%s'  "
    update_node = "UPDATE c_NODE SET in_hits = %d, out_hits = %d WHERE id_Node = '%s'"
    conn = openDataBase(DATABASE)
    c = conn.cursor()
    c.execute(search_all_nodes)
    for i in c.fetchall():
        id = int(i[0])
        if args.verbose:
            print('Manage {0}').format(id)
        select_num_sources = "SELECT SUM(hits), COUNT(hits) FROM t_GRAPH WHERE source = '{0}'".format(id)
        c.execute(select_num_sources)
        dst = c.fetchone()
        if args.verbose:
            print ('src hits {0}\t src num {1}').format(dst[0],dst[1])
        select_num_destinations = "SELECT SUM(hits), COUNT(hits) FROM t_GRAPH WHERE destination = '{0}'".format(id)
        c.execute(select_num_destinations)
        src = c.fetchone()
        if args.verbose:
            print ('dst hits {0}\t dst num {1}').format(src[0],src[1])
        update_node = "UPDATE c_NODE SET in_hits = '{0}', in_num = '{1}', out_hits = '{2}', out_num = '{3}' WHERE id_Node = '{4}'".format(src[0],src[1],dst[0],dst[1],id)
        #print update_node
        c.execute(update_node)

    conn.commit()
    conn.close()

#-----------------------------------------------------------------------
def ddbb_node(con, c, node, deep, in_num, out_num, in_hits, out_hits, original):
    search_node = "SELECT id_Node, hits FROM c_NODE WHERE literal = '%s' and deep = %d"
    insert_node = "INSERT INTO c_NODE \
        ( literal, hits, deep, in_hits, out_hits, in_num, out_num, Original )\
         VALUES ( '%s',%d, %d, %d, %d, %d, %d, '%s' )"
    update_node = "UPDATE c_NODE SET hits = %d WHERE id_Node = '%s'"
    search_node = search_node % (node.encode('utf-8'),deep)
    c.execute(search_node)
    data = c.fetchone()
    if not data:
        insert_node = insert_node % (node.encode('utf-8'), 1, deep, in_num, out_num, in_hits, out_hits, original)
        c.execute(insert_node)
        c.execute(search_node)
        data = c.fetchone()
        print "+",
    else:
        hits = data[1] + 1
        update_node = update_node % (int(hits) , data[0])
        c.execute(update_node)
        print "-",
    con.commit
    return data[0]
#-----------------------------------------------------------------------
def ddbb_link(con, c, source, destination, num_hits):
    search_link = "SELECT source, hits FROM t_GRAPH WHERE source = '%s' and destination = '%s'"
    insert_link = "INSERT INTO t_GRAPH ( source, destination, hits ) VALUES ('%s','%s',%d)"
    update_link = "UPDATE t_GRAPH SET hits = %d WHERE source = '%s' and  destination = '%s' "
    search_link = search_link % (source, destination)
    c.execute(search_link)
    data = c.fetchone()
    if not num_hits:
        num_hits = 1
    if not data:
        insert_link = insert_link % (source, destination, num_hits)
        c.execute(insert_link)
        c.execute(search_link)
        data = c.fetchone()
        print "*",
    else:
        if not source:
            hits = 1
        else:
            hits = data[1] + 1
            update_link = update_link % (int(hits) , source, destination)
        c.execute(update_link)
        print "-",
    con.commit
#-----------------------------------------------------------------------
############  GRAPH
def graph_creation (file, DATABASE) :
#------------------------
    def insert_string ( aux, path, conn, c, deep, id_node_old ):
        path += 1
        for item in aux.split(args.delimiter):
                if re.search ( '^((l[aeo]s?)|de(l)?|por|a|el|con|que|en|al|se|nos)$', item.lower() ):
                    if args.verbose:
                        print "jump {0}".format( item.encode( 'latin-1' ))
                    else:
                        print "j",
                    continue
                deep+=1
                if re.search('', item.encode( 'utf-8' )):
                    if args.verbose:
                        print "\nERROR:{0}".format ( item.encode( 'utf-8' ) )
                    item ="B@DCODE"
                    print "X",
                if re.search ( '[á|é|í|ó|ú]', item.lower() ):
                    item = elimina_tildes ( item )
                id_node = ddbb_node(conn, c, item.lower(), deep, 0, 0, 0, 0, True )
                if not id_node_old:
                    ddbb_link(conn, c, "0", id_node, 0)
                else:
                    ddbb_link(conn, c, id_node_old, id_node, 0)
                id_node_old = id_node
        return ( path )
 #------------------------
    conn = openDataBase(DATABASE)
    c = conn.cursor()
    aux = ""
    inicio = 1
    deep = 0
    linecont = 0
    path=0
    cont=0
    for line in codecs.open(file, 'r', encoding='ISO-8859-1', errors='ignore'):
        print "\n[{0}]".format(linecont),
        linecont += 1
        if args.verbose:
            print "\t["+str(cont)+"] "+line
        line = date_identificator(line)
        line = strip_string(line)
        line = re.sub('\n$', " ", line).strip()
        flag = (line.split(args.delimiter, minNode)[0]).isdigit()
        #if args.verbose:
        #    print "\t[DATE CHANGED]{0}".format ( line.encode( 'utf-8' ) )
        #    print "\tcont={0}".format ( cont )
        #    print "\tAUX:<{0}>".format ( aux.encode('utf-8') )
        #    print "\tCHECK[{}]".format ( line.split(args.delimiter, minNode)[0] )
        if inicio and flag :
            if args.verbose:
                print "<1>"
            aux = line
            inicio = 0
        elif not( inicio ) and flag :
            if args.verbose:
                print "<2>"
            id_node_old = 0
            deep=0
            # cambio aux por line
            if args.verbose:
                print "[INSERT][BUCLE]({0})".format ( aux.encode( 'utf-8' ) )
            path = insert_string ( aux, path, conn, c, deep, id_node_old )
            aux = line
        elif not flag :
            if args.verbose:
                print "<3>"
            if args.verbose:
                print "LL",
            line = re.sub('^mac', "", line).strip()
            aux += args.delimiter + line
    print "\n[{0}]".format(linecont),
    path = insert_string ( aux, path, conn, c, deep, id_node_old )
    print "\n\n\t{0} Lines with paths".format( path )
    print "\t{0} Lines read".format( linecont )

    conn.close()
#-----------------------------------------------------------------------
def get_nodes(c,dot,item):
    c.execute ("SELECT literal FROM c_NODE WHERE id_Node = {0}".format(item))
    data = c.fetchone()
    dot.node(str(item),data[0].format('ascii'))
#-----------------------------------------------------------------------
def get_edges( c, src, destination_node,dot):
    select_src_dst = "select destination,hits from t_graph where source = '%d'"
    select_src_dst = select_src_dst % int(src)
    c.execute(select_src_dst)
    for i in c.fetchall():
        dot.edge(str(src), str(i[0]),str(i[1]))
        if int(src):
            get_nodes (c,dot,src)
        get_nodes (c,dot,i[0])
        if not i[0] in destination_node:
            destination_node.add (i[0])
            get_edges(c, i[0], destination_node,dot)
#-----------------------------------------------------------------------
def MinNumberofElements(file):
    MNE=9999999999999999
    if os.path.exists(file):
        for line in codecs.open (file,'r', encoding='ISO-8859-1'):
            #print sys.stdout.encoding
            #print line
            #print line.decode('iso-8859-1').encode('utf8'),
            if ( re.search ( "^\d{1,2}\/\d{1,2}\/\d{4} \d{2}:\d{2}:\d{2}", line)):
                line = date_identificator(line)
                line = strip_string(line)
                line = re.sub('\n$', " ", line).strip()
                if MNE> len(line.split(' ')):
                    if args.verbose:
                        print line
                    MNE = len(line.split(' '))
    print "Minumun lenght : {0}".format(MNE)
    return MNE
#-----------------------------------------------------------------------
#-----------------------------------------------------------------------
def GraphNormalize():
    if args.filename:
        MNE=MinNumberofElements(args.filename)
    elif args.jumpNode:
        MNE=args.jumpNode
    else:
        print "you need a start position -k -f <filename>"
        sys.exit(0)
    conn = openDataBase (DATABASE)
    c = conn.cursor()
    # Primera aproximación orígenes de n - 1
    select_n = "select literal, id_Node, deep, in_hits, out_hits, in_num from c_node \
        where in_num > 1 and out_num = 1 and deep >= {0}".format(MNE)
    c.execute(select_n)
    for i in c.fetchall():
        stack=[]
        deep = i[2]
        if args.verbose:
            print ("\n[N-1] literal:{0}\t[id:{1}][deep:{2}]OUT_NUM:{3}\n".format(i[0].encode('utf-8'),i[1],i[2],i[3]))
        stack.append([i[0],i[1]])
        stack=recSon ( conn, c, i[1], stack )
        if stack is None:
            print "ein?"
        elif (len ( stack ) > 1 ):
            mgmtStack (conn, c,stack, i[2], i[3], i[4], i[5])
    select_n = "select literal, id_Node, deep, in_hits, out_hits, in_num from c_node \
        where in_num >= 1 and out_num = 1 and deep >= {0}".format(int(MNE)+1)
    c.execute(select_n)
    for i in c.fetchall():
        stack=[]
        deep = i[2]
        if args.verbose:
            print ("\n[1-1] literal:{0}\t[id:{1}][deep:{2}]OUT_NUM:{3}\n".format(i[0].encode('utf-8'),i[1],i[2],i[3]))
        stack.append([i[0],i[1]])
        stack=recSon ( conn, c, i[1], stack )
        if stack is None:
            print "ein?"
        elif (len ( stack ) > 1 ):
            mgmtStack (conn, c,stack, i[2], i[3], i[4], i[5])

    conn.close()
#-----------------------------------------------------------------------
def recSon (con, c, nodeid, stack):
    if args.verbose:
            print "recSon ({0})[{1}]".format(nodeid, stack)
    next_hop = "SELECT literal, destination, in_num, out_num  FROM t_graph\
                    join c_node ON\
                    id_node = destination\
                    WHERE source = {0}".format (nodeid)
    c.execute (next_hop)
    i=c.fetchone()
    if args.verbose:
            print i
    if not (i is None):
        if i[2] == 1:
            if i[3] <= 1:
                stack.append([i[0],i[1]])
                recSon (con, c,i[1],stack)
            else:
                stack.append([i[0],i[1]])
                return ( stack )
    return ( stack )
#-----------------------------------------------------------------------
def mgmtStack (con, c, stack, deep, in_hits, out_hits, in_num):
    def create_new_data ( con, c, old_node, string, deep, in_hits, out_hits, in_num, node_list, src ):
        dst = list_nodes(c, old_node, 'source')
        if args.verbose:
                print "\t\tNEW string:{0}".format(string.encode('utf-8'))
        else:
            print "#",
        id_node_new = ddbb_node(con, c, string, deep, in_num, 1, in_hits, out_hits, 'False' )
        for node_old in node_list:
            c.execute ( "INSERT INTO t_CHANGES \
                ( id_changed, id_original )\
             VALUES ( {0}, {1} )".format ( id_node_new, node_old ) )
             #con.commit
        for item in src:
            if args.verbose:
                print "\t\t\t[SRC]\tsrc:{0} -> dst:{1} ({2}) ADDED !!!".format(item[0], id_node_new, item[1])
            else:
                print "+",
            ddbb_link(con, c, item[0], id_node_new, item[1])
        for item in dst:
            if args.verbose:
                print "\t\t\t[DST]\tsrc:{0} -> dst:{1} ({2}) ADDED !!!".format( id_node_new, item[0], item[1]    )
            else:
                print "+"
            c.execute ( "DELETE FROM t_graph WHERE\
            source = {0} and destination = {1}".format( item[0], old_node ) )
            if args.verbose:
                print "\t\t\tsrc:{0} -> dst:{1} DELETED !!!".format(item[0], old_node)
            else:
                print "=",
            ddbb_link(con, c, id_node_new, item[0], item[1] )
#------------------------
    if args.verbose:
            print ("\nmgmtStack [{0}]({1})".format(stack, deep))
    cont=0
    src=[]
    string=""
    old_node = ""
    node_list = []

    for nodo in stack:
        if args.verbose:
            print "\t\t",nodo
            print "\t\tbucle elemento [{0}]({1})".format( nodo[0].encode('utf-8'), nodo[1] )
        if cont == 0:
            src = list_nodes(c, nodo[1], 'destination')
        if not string:
            node_list.append( nodo[1] )
            string = nodo[0]
        else:
            node_list.append( nodo[1] )
            string = string + args.delimiter + nodo[0]

        if args.verbose:
            print "\t\t({2}) Managing old nodes : {0} -> {1}[{3}]".format ( old_node, nodo[1], cont, src )

        if (len (src) == 1) and cont == 0:
            c.execute ( "DELETE FROM t_graph WHERE\
            source = {0} and destination = {1}".format( src[0][0], nodo[1]) )
            if args.verbose:
                print "\t\t\tsrc:{0} -> dst:{1} DELETED !!!".format(old_node, nodo[1])
            else:
                print "=",
        elif cont == 0:
            for n in src:
                c.execute ( "DELETE FROM t_graph WHERE\
                source = {0} and destination = {1}".format(n[0],nodo[1]))
                if args.verbose:
                    print "\t\t\tsrc:{0} -> dst:{1} DELETED !!!".format(n[0], nodo[1])
                else:
                    print "=",
        else:
            c.execute ( "DELETE FROM t_graph WHERE\
            source = {0} and destination = {1}".format( old_node, nodo[1]) )
            if args.verbose:
                print "\t\t\tsrc:{0} -> dst:{1} DELETED !!!".format(old_node, nodo[1])
            else:
                print "=",
        old_node = nodo[1]
        cont += 1

# MAC
    if args.verbose:
        print "\t\t\tsrc:{0} -> dst:{1} DELETED !!!".format(old_node, nodo[1])
    else:
        print "=",
    create_new_data ( con, c, old_node, string, deep, in_hits, out_hits, in_num, node_list, src )
    node_list= []
    if args.verbose:
            print "+++++"
    else:
            print
#-----------------------------------------------------------------------
def list_nodes (c,id, subject):
    if args.verbose:
            print ("\tlist_nodes id:{0} subject:{1}".format(id, subject))
    lista=[]
    if subject == "source":
        aux = "destination"
    else:
        aux = "source"
    search_node = "select {2}, hits from t_graph where {1} = {0}".format(id,subject,aux)
    if args.verbose:
        print "\t\t\t{{0}}\tID:{1}".format (subject, search_node)
    c.execute(search_node)
    for i in  c.fetchall():
        lista.append([i[0], i[1]])
    return lista
#-----------------------------------------------------------------------
def recSTR (con, c, nodeid, str):
    if args.verbose:
            print "recSTR ({0})[{1}]".format(nodeid, str)
    next_hop = "SELECT literal, destination  FROM t_graph\
                    join c_node ON\
                    id_node = destination\
                    WHERE source = {0}".format (nodeid)
    if args.verbose:
        #print next_hop
        print "\t\t recSTR str:[{0}]".format (str)

    c.execute (next_hop)
    destinations = c.fetchall()
    if destinations:
        for i in destinations:
            if args.verbose:
                    print "\t\t recSTR [{0}]".format (i[0].encode('utf-8'))
            if not (i is None):
                recSTR (con, c,i[1], str+args.delimiter + i[0].encode('utf-8'))
            else:
                print "\t",str
                str = ""
                return str
    else:
        print "\t",str
        str = ""
        return str
#-----------------------------------------------------------------------
def GrammarExtraction():
    conn = openDataBase (DATABASE)
    c = conn.cursor()
    # Primera aproximación orígenes de n - 1
    select_n = "select literal, id_Node from c_node \
        where deep = 2"
    c.execute(select_n)
    for i in c.fetchall():
        stack=[]
        if args.verbose:
            print ("\n[GE] literal:{0}\t[id:{1}]\n".format(i[0].encode('utf-8'),i[1]))
        str = i[0].encode('utf-8')
        recSTR ( conn, c, i[1], str )
#-----------------------------------------------------------------------
#-----------------------------------------------------------------------
#-----------------------------------------------------------------------
#-----------------------------------------------------------------------
#-----------------------------------------------------------------------
print "\n\n"
if args.create:
    create_all_databases(DATABASE)

if args.directory:
    for root, directories, filenames in os.walk(args.directory):
        for filename in filenames:
            absolutePath = os.path.join(root,filename)
            if (re.findall ( "log$", filename )) and not(re.findall ( "auditoria|sistema|Crypto|Tsec", filename ) ) :
                print "\n",absolutePath
                mgmtFILE(absolutePath)
elif args.filename and os.path.exists(args.filename):
    showContents(args.filename)
if args.graph and args.filename:
    graph_creation(args.filename,DATABASE)
if args.central:
    centrality(DATABASE)

if  (not args.GraphNormalize) and ( args.KnowMN and args.filename ):
    if args.verbose:
        print "KnowMN"
    MinNumberofElements(args.filename)
elif args.GraphNormalize:
    if args.verbose:
        print "GraphNormalize"
    GraphNormalize()

if args.graphviz:
    dot = gv.Digraph(comment='The Round Table')
    conn = openDataBase(DATABASE)
    c = conn.cursor()
    destination_node = set(["root"])
    get_edges(c, "0", destination_node,dot)
    conn.close
    print
    # pon el formato como parametro
    dot.format = 'svg'
    dot.render('img/graph', view=True)

if  (args.ShowGrammar):
    if args.verbose:
        print "ShowGrammar"
    GrammarExtraction()


print "\n\n\n   eof"
# 933
