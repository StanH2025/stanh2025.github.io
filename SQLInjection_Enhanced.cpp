#include <algorithm>
#include <iostream>
#include <locale>
#include <tuple>
#include <vector>
#include <regex>
#include <string>
#include <ctime>
#include <cstdlib>

#include "sqlite3.h"

// using a tuple to store user info (id, name, password)
typedef std::tuple<std::string, std::string, std::string> user_record;

// this is just used to check if a query has a WHERE clause
const std::string str_where = " where ";

// forward declaration so sqlite can use this callback before it is fully defined
static int callback(void* possible_vector, int argc, char** argv, char** azColName);

// this function converts the SQL query to lowercase so it's easier to check patterns
std::string normalize_sql(const std::string& sql)
{
    std::string normalized = sql;

    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    return normalized;
}

// this checks if the query even has a WHERE clause
// because injection usually happens there
bool has_where_clause(const std::string& normalized_sql)
{
    return normalized_sql.find(str_where) != std::string::npos;
}

// this is where I check if the SQL looks like an injection attempt
bool is_suspected_injection(const std::string& sql)
{
    // first normalize the query so case doesn’t matter
    std::string normalized = normalize_sql(sql);

    // if there’s no WHERE clause, I skip checking
    if (!has_where_clause(normalized))
    {
        return false;
    }

    // regex looks for patterns like: OR 1=1 or 'a'='a'
    const std::regex injection_pattern(
        R"(\bor\b\s+('([^']*)'|\d+(\.\d+)?)\s*=\s*('([^']*)'|\d+(\.\d+)?)\s*;?\s*$)",
        std::regex_constants::ECMAScript
    );

    // if it finds the pattern, I treat it as a possible injection
    return std::regex_search(normalized, injection_pattern);
}

// this runs the SQL query if it passes validation
bool execute_sql(sqlite3* db, const std::string& sql, std::vector<user_record>& records)
{
    char* error_message = nullptr;

    // run query and store results
    if (sqlite3_exec(db, sql.c_str(), callback, &records, &error_message) != SQLITE_OK)
    {
        std::cout << "Query failed: " << error_message << std::endl;
        sqlite3_free(error_message);
        return false;
    }

    return true;
}

// callback function for sqlite (used to collect query results)
static int callback(void* possible_vector, int argc, char** argv, char** azColName)
{
    if (possible_vector == NULL)
    {
        // if no vector is passed, just print results
        for (int i = 0; i < argc; i++)
        {
            std::cout << azColName[i] << " = "
                      << (argv[i] ? argv[i] : "NULL") << std::endl;
        }
        std::cout << std::endl;
    }
    else
    {
        // otherwise store results in a vector
        std::vector<user_record>* rows =
            static_cast<std::vector<user_record>*>(possible_vector);

        rows->push_back(std::make_tuple(argv[0], argv[1], argv[2]));
    }
    return 0;
}

// creates database and inserts sample users
bool initialize_database(sqlite3* db)
{
    char* error_message = NULL;

    // creating USERS table
    std::string sql = "CREATE TABLE USERS("
        "ID INT PRIMARY KEY NOT NULL,"
        "NAME TEXT NOT NULL,"
        "PASSWORD TEXT NOT NULL);";

    if (sqlite3_exec(db, sql.c_str(), callback, NULL, &error_message) != SQLITE_OK)
    {
        std::cout << "Failed to create table: " << error_message << std::endl;
        sqlite3_free(error_message);
        return false;
    }

    std::cout << "USERS table created." << std::endl;

    // inserting test data
    sql = "INSERT INTO USERS VALUES (1, 'Fred', 'Flinstone');"
          "INSERT INTO USERS VALUES (2, 'Barney', 'Rubble');"
          "INSERT INTO USERS VALUES (3, 'Wilma', 'Flinstone');"
          "INSERT INTO USERS VALUES (4, 'Betty', 'Rubble');";

    if (sqlite3_exec(db, sql.c_str(), callback, NULL, &error_message) != SQLITE_OK)
    {
        std::cout << "Insert failed: " << error_message << std::endl;
        sqlite3_free(error_message);
        return false;
    }

    return true;
}

// main function that handles query validation before execution
bool run_query(sqlite3* db, const std::string& sql, std::vector<user_record>& records)
{
    records.clear();

    // check if query looks like SQL injection
    if (is_suspected_injection(sql))
    {
        std::cout << "SECURITY ALERT: Possible SQL injection blocked." << std::endl;
        std::cout << "Blocked SQL: " << sql << std::endl << std::endl;
        return false;
    }

    // if safe, execute query
    return execute_sql(db, sql, records);
}

// this simulates SQL injection attacks
bool run_query_injection(sqlite3* db, const std::string& sql, std::vector<user_record>& records)
{
    std::string injectedSQL = sql;
    std::string localCopy = normalize_sql(sql);

    // only inject if there is a WHERE clause
    if (has_where_clause(localCopy))
    {
        // remove semicolon if the original query already ends with one
        if (!injectedSQL.empty() && injectedSQL.back() == ';')
        {
            injectedSQL.pop_back();
        }

        // randomly inject common attack patterns
        switch (rand() % 4)
        {
        case 1:
            injectedSQL += " or 2=2;";
            break;
        case 2:
            injectedSQL += " or 'hi'='hi';";
            break;
        case 3:
            injectedSQL += " or 'hack'='hack';";
            break;
        default:
            injectedSQL += " or 1=1;";
            break;
        }
    }

    return run_query(db, injectedSQL, records);
}

// prints query results
void dump_results(const std::string& sql, const std::vector<user_record>& records)
{
    std::cout << "\nSQL: " << sql
              << " ==> " << records.size() << " records found." << std::endl;

    for (auto record : records)
    {
        std::cout << "User: " << std::get<1>(record)
                  << " [UID=" << std::get<0>(record)
                  << " PWD=" << std::get<2>(record) << "]" << std::endl;
    }
}

// runs test queries
void run_queries(sqlite3* db)
{
    std::vector<user_record> records;

    // normal query
    std::string sql = "SELECT * from USERS";
    if (!run_query(db, sql, records)) return;
    dump_results(sql, records);

    // query with WHERE clause
    sql = "SELECT ID, NAME, PASSWORD FROM USERS WHERE NAME='Fred'";
    if (!run_query(db, sql, records)) return;
    dump_results(sql, records);

    // simulate injections
    for (int i = 0; i < 5; i++)
    {
        if (!run_query_injection(db, sql, records)) continue;
        dump_results(sql, records);
    }
}

// main program
int main()
{
    srand(static_cast<unsigned int>(time(nullptr)));

    sqlite3* db = NULL;

    if (sqlite3_open(":memory:", &db) != SQLITE_OK)
    {
        std::cout << "Database connection failed: " << sqlite3_errmsg(db) << std::endl;
        return -1;
    }

    std::cout << "Connected to database." << std::endl;

    if (!initialize_database(db))
    {
        std::cout << "Database setup failed." << std::endl;
        sqlite3_close(db);
        return -1;
    }

    run_queries(db);

    sqlite3_close(db);

    return 0;
}