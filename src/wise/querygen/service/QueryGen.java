package wise.querygen.service;

import java.util.ArrayList;
import java.util.Hashtable;

import wise.querygen.clauses.*;
import wise.querygen.dto.*;

public class QueryGen implements IQueryGen {

	
	protected boolean _distinct = false;
    protected TopClause _topClause = new TopClause(100, TopUnit.Percent);
    protected ArrayList<String> _selectedColumns = new ArrayList<String>();	// array of string
    protected ArrayList<String> _selectedTables = new ArrayList<String>();	// array of string
    protected ArrayList<JoinClause> _joins = new ArrayList<JoinClause>();	// array of JoinClause
    protected WhereStatement _whereStatement = new WhereStatement();
    protected ArrayList<OrderByClause> _orderByStatement = new ArrayList<OrderByClause>();	// array of OrderByClause
    protected ArrayList<String> _groupByColumns = new ArrayList<String>();		// array of string
    protected WhereStatement _havingStatement = new WhereStatement();
    
    
	public WhereStatement get_whereStatement() {
		return _whereStatement;
	}


	public void set_whereStatement(WhereStatement _whereStatement) {
		this._whereStatement = _whereStatement;
	}
	
	
	public boolean is_distinct() {
		return _distinct;
	}


	public void set_distinct(boolean _distinct) {
		this._distinct = _distinct;
	}


	public TopClause get_topClause() {
		return _topClause;
	}


	public void set_topClause(TopClause _topClause) {
		this._topClause = _topClause;
	}


	public ArrayList<String> get_selectedColumns() {
		return _selectedColumns;
	}


	public void set_selectedColumns(ArrayList<String> _selectedColumns) {
		this._selectedColumns = _selectedColumns;
	}


	public ArrayList<String> get_selectedTables() {
		return _selectedTables;
	}


	public void set_selectedTables(ArrayList<String> _selectedTables) {
		this._selectedTables = _selectedTables;
	}


	public ArrayList<JoinClause> get_joins() {
		return _joins;
	}


	public void set_joins(ArrayList<JoinClause> _joins) {
		this._joins = _joins;
	}


	public ArrayList<OrderByClause> get_orderByStatement() {
		return _orderByStatement;
	}


	public void set_orderByStatement(ArrayList<OrderByClause> _orderByStatement) {
		this._orderByStatement = _orderByStatement;
	}


	public ArrayList<String> get_groupByColumns() {
		return _groupByColumns;
	}


	public void set_groupByColumns(ArrayList<String> _groupByColumns) {
		this._groupByColumns = _groupByColumns;
	}


	public WhereStatement get_havingStatement() {
		return _havingStatement;
	}


	public void set_havingStatement(WhereStatement _havingStatement) {
		this._havingStatement = _havingStatement;
	}


	public QueryGen() { }
	
	public void SelectAllColumns()
    {
        _selectedColumns.clear();
    }
    public void SelectCount()
    {
        SelectColumn("count(1)");
    }
    public void SelectColumn(String column)
    {
        _selectedColumns.clear();
        _selectedColumns.add(column);
    }
    public void SelectColumns(ArrayList<String> columns)
    {
       _selectedColumns.clear();
       
       for (String column : columns)
       {
          _selectedColumns.add(column);
       }
    }
    public void SelectFromTable(String table)
    {
        _selectedTables.clear();
        _selectedTables.add(table);
    }
    public void SelectFromTables(ArrayList<String> tables)
    {
        _selectedTables.clear();
        for (String Table : tables)
        {
            _selectedTables.add(Table);
        }
    }
    
    public void AddJoin(JoinClause newJoin)
    {
        _joins.add(newJoin);
    }
    public void AddJoin(JoinType join, String toTableName,String toColumnName, Comparison operator, String fromTableName, String fromColumnName)
    {
        JoinClause NewJoin = new JoinClause(join, toTableName, toColumnName, operator, fromTableName, fromColumnName);
        _joins.add(NewJoin);
    }
    
    
    public void AddWhere(WhereClause clause) { AddWhere(clause, 1); }
    public void AddWhere(WhereClause clause, int level)
    {
        _whereStatement.Add(clause, level);
    }
    public WhereClause AddWhere(String field, Comparison operator, Object compareValue, String valuetype, String paramName) 
    { 
        return AddWhere(field, operator, compareValue, 1, valuetype, paramName); 
    }
    public WhereClause AddWhere(Enum field, Comparison operator, Object compareValue, String valuetype, String paramName) 
    { 
        return AddWhere(field.toString(), operator, compareValue, 1, valuetype, paramName); 
    }
    public WhereClause AddWhere(String field, Comparison operator, Object compareValue, int level, String valuetype, String paramName)
    {
        return AddWhere(field, operator, compareValue, level, valuetype, paramName, LogicOperator.And);
    }

    public WhereClause AddWhere(String field, Comparison operator, Object compareValue, int level, String valuetype, String paramName, LogicOperator aLogicOperator)
    {
        WhereClause NewWhereClause = new WhereClause(field, operator, compareValue, valuetype, paramName, aLogicOperator);
        _whereStatement.Add(NewWhereClause, level);
        return NewWhereClause;
    }
	
    public void AddOrderBy(OrderByClause clause)
    {
        _orderByStatement.add(clause);
    }
    public void AddOrderBy(Enum field, Sorting order) { this.AddOrderBy(field.toString(), order); }
    public void AddOrderBy(String field, Sorting order)
    {
        OrderByClause NewOrderByClause = new OrderByClause(field, order);
        _orderByStatement.add(NewOrderByClause);
    }
    public void GroupBy(ArrayList<String> columns)
    {
        for (String Column : columns)
        {
            _groupByColumns.add(Column);
        }
    }

    public void AddHaving(WhereClause clause) { AddHaving(clause, 1); }
    public void AddHaving(WhereClause clause, int level)
    {
        _havingStatement.Add(clause, level);
    }
    public WhereClause AddHaving(String field, Comparison operator, Object compareValue, String valuetype, String paramName) { return AddHaving(field, operator, compareValue, 1, valuetype, paramName); }
    public WhereClause AddHaving(Enum field, Comparison operator, Object compareValue, String valuetype, String paramName) { return AddHaving(field.toString(), operator, compareValue, 1, valuetype, paramName); }
    public WhereClause AddHaving(String field, Comparison operator, Object compareValue, int level, String valuetype, String paramName)
    {
        return AddHaving(field, operator, compareValue, level, valuetype, paramName, LogicOperator.And);
    }

    public WhereClause AddHaving(String field, Comparison operator, Object compareValue, int level, String valuetype, String paramName, LogicOperator aLogicOperator)
    {
        WhereClause NewWhereClause = new WhereClause(field, operator, compareValue, valuetype, paramName, aLogicOperator);
        _havingStatement.Add(NewWhereClause, level);
        return NewWhereClause;
    }
    
    
	@Override
	public String BuildQuery() {
		// TODO Auto-generated method stub
		return (String)this.BuildQuery(false);
	}
	
	private Object BuildQuery(boolean buildCommand)
    {
        
		String Query = "SELECT\t" + "\t";

        // Output Distinct
        if (_distinct)
        {
            Query += "DISTINCT ";
        }

        // Output Top clause
        if (!(_topClause.Quantity == 100 & _topClause.Unit == TopUnit.Percent))
        {
            Query += "TOP " + _topClause.Quantity;
            if (_topClause.Unit == TopUnit.Percent)
            {
                Query += " PERCENT";
            }
            Query += " ";
        }

        // Output column names
        if (_selectedColumns.size() == 0)
        {
            if (_selectedTables.size() == 1)
                Query += _selectedTables.get(0) + "."; // By default only select * from the table that was selected. If there are any joins, it is the responsibility of the user to select the needed columns.

            Query += "*";
        }
        else
        {
            for (String ColumnName : _selectedColumns)
            {
                Query += ColumnName + ',';
            }
            //확인 필요
            Query = Query.replaceAll("[,]+$", "");// Trim de last comma inserted by foreach loop
           // Query = Query.trim().replaceAll("^[,]+", "");
            Query += ' ';
        }

        Query += "\r";

        // Output table names
        if (_selectedTables.size() > 0)
        {
            Query += "FROM" + "         ";
            for (String TableName : _selectedTables)
            {
                Query += TableName + ',';
            }
          //확인 필요
            Query = Query.replaceAll("[,]+$", ""); // Trim de last comma inserted by foreach loop
            Query += ' ';
        }

        // Output joins
        if (_joins.size() > 0)
        {
            Hashtable<String,String> hshTable = new Hashtable<String,String>();
            String JoinString = "";

            for (JoinClause sClause : _joins)
            {
            	
                String comptable = "";
                int loopcnt = 0;
                comptable = sClause.FromTable + sClause.ToTable;

                if (!hshTable.contains(comptable))
                {

                    switch (sClause.JoinType)
                    {
                        case InnerJoin: JoinString = "INNER JOIN"; break;
                        case OuterJoin: JoinString = "FULL OUTER JOIN"; break;
                        case LeftJoin: JoinString = "LEFT JOIN"; break;
                        case RightJoin: JoinString = "RIGHT JOIN"; break;
                    }
                    JoinString += " " + sClause.ToTable + " ON ";


                    for (JoinClause SubClause : _joins)
                    {
                        if (comptable.equalsIgnoreCase(SubClause.FromTable + SubClause.ToTable))
                        {
                            if (loopcnt == 0)
                            {
                                JoinString += WhereStatement.CreateComparisonClause(SubClause.FromColumn, SubClause.ComparisonOperator, new SqlLiteral(SubClause.ToColumn), "SqlLiteral", "");
                                loopcnt += 1;

                            }
                            else
                            {
                                JoinString += " AND " + WhereStatement.CreateComparisonClause(SubClause.FromColumn, SubClause.ComparisonOperator, new SqlLiteral(SubClause.ToColumn), "SqlLiteral", "");
                            }
                        }
                    }

                    hshTable.put(comptable, comptable);
                    Query += JoinString + "\r\t\t\t";
                }
            }
        }

        Query += "\r";

        // Output where statement
        if (_whereStatement.getClauseLevels() > 0)
        {
            if (buildCommand)
                Query += "WHERE\t\t" + _whereStatement.BuildWhereStatement();
            else
                Query += "WHERE\t\t" + _whereStatement.BuildWhereStatement();
        }

        Query += "\r";

        // Output GroupBy statement
        if (_groupByColumns.size() > 0)
        {
            Query += " GROUP BY ";
            for(String Column : _groupByColumns)
            {
                Query += Column + ',';
            }
            Query = Query.replaceAll("[,]+$", "");
            Query += ' ';
        }

        Query += "\r";

        // Output having statement
        if (_havingStatement.getClauseLevels() > 0)
        {
            // Check if a Group By Clause was set
            //if (_groupByColumns.Count == 0)
            //{
            //    throw new Exception("Having statement was set without Group By");
            //}
            if (buildCommand)
                Query += " HAVING " + _havingStatement.BuildWhereStatement();
            else
                Query += " HAVING " + _havingStatement.BuildWhereStatement();
        }

        Query += "\r";

        // Output OrderBy statement
        if (_orderByStatement.size() > 0)
        {
            Query += " ORDER BY ";
            for (OrderByClause Clause : _orderByStatement)
            {
                String OrderByClause = "";
                switch (Clause.SortOrder)
                {
                    case Ascending:
                        OrderByClause = Clause.FieldName + " ASC"; break;
                    case Descending:
                        OrderByClause = Clause.FieldName + " DESC"; break;
                }
                Query += OrderByClause + ',';
            }
            Query  = Query.replaceAll("[,]+$", ""); // Trim de last AND inserted by foreach loop
            Query += ' ';
        }

      /*  if (buildCommand)
        {
            // Return the build command
            command.CommandText = Query;
            return command;
        }
        else
        {*/
            // Return the built query
            return Query;
       // }
    }
	public String BuildQuerySelect()
    {
        return (String)this.BuildQuerySelect(false);
    }
	
	public String BuildQuerySelectDistinct()
    {
        return (String)this.BuildQuerySelectDistinct(false);
    }
	
	 private Object BuildQuerySelect(boolean buildCommand)
     {
         String Query = "SELECT" + "  ";

         // Output Distinct
         if (_distinct)
         {
             Query += "DISTINCT ";
         }

         // Output Top clause
         if (!(_topClause.Quantity == 100 & _topClause.Unit == TopUnit.Percent))
         {
             Query += "TOP " + _topClause.Quantity;
             if (_topClause.Unit == TopUnit.Percent)
             {
                 Query += " PERCENT";
             }
             Query += " ";
         }

         // Output column names
         if (_selectedColumns.size() == 0)
         {
             if (_selectedTables.size() == 1)
                 Query += _selectedTables.get(0) + "."; // By default only select * from the table that was selected. If there are any joins, it is the responsibility of the user to select the needed columns.

             Query += "*";
         }
         else
         {
             boolean bFirst = false;

             for (String ColumnName : _selectedColumns)
             {
                 if (!bFirst)
                 {
                     Query += ColumnName + ',';
                     bFirst = true;
                 }
                 else
                 {
                     Query = Query + '\r' + "        " + ColumnName + ',';
                 }
             }
             Query =  Query.replaceAll("[,]+$", ""); // Trim de last comma inserted by foreach loop
             Query += ' ';
         }


             // Return the built query
         return Query;
         
     }
	 
	 private Object BuildQuerySelectDistinct(boolean buildCommand)
     {
         String Query = "SELECT" + "  ";

         // Output Distinct
         Query += "DISTINCT ";

         // Output Top clause
         if (!(_topClause.Quantity == 100 & _topClause.Unit == TopUnit.Percent))
         {
             Query += "TOP " + _topClause.Quantity;
             if (_topClause.Unit == TopUnit.Percent)
             {
                 Query += " PERCENT";
             }
             Query += " ";
         }

         // Output column names
         if (_selectedColumns.size() == 0)
         {
             if (_selectedTables.size() == 1)
                 Query += _selectedTables.get(0) + "."; // By default only select * from the table that was selected. If there are any joins, it is the responsibility of the user to select the needed columns.

             Query += "*";
         }
         else
         {
             boolean bFirst = false;

             for (String ColumnName : _selectedColumns)
             {
                 if (!bFirst)
                 {
                     Query += ColumnName + ',';
                     bFirst = true;
                 }
                 else
                 {
                     Query = Query + '\r' + "        " + ColumnName + ',';
                 }
             }
             Query =  Query.replaceAll("[,]+$", ""); // Trim de last comma inserted by foreach loop
             Query += ' ';
         }


             // Return the built query
         return Query;
         
     }
	 
	 public String BuildQueryFrom()
     {
         return (String)this.BuildQueryFrom(false);
     }
	 
	 private Object BuildQueryFrom(boolean buildCommand)
     {
         String Query = "";

         // Output table names
         if (_selectedTables.size() > 0)
         {
             Query += "FROM" + "    ";
             for(String TableName : _selectedTables)
             {
             	/* DOGFOOT ktkang 대시보드 주제영역 필터 오류 수정  20200708 */
            	 if(!TableName.equals("")) {
            		 Query += TableName + ',';
            	 }
             }
             Query = Query.replaceAll("[,]+$", ""); // Trim de last comma inserted by foreach loop
             Query += ' ';
         }

         // Output joins
         if (_joins.size() > 0)
         {
             Hashtable<String,String> hshTable = new Hashtable<String,String> ();
             String JoinString = "";

             for (JoinClause sClause : _joins)
             {
                 String comptable = "";
                 int loopcnt = 0;

                 comptable = sClause.FromTable + sClause.ToTable;

                 if (!hshTable.contains(comptable))
                 {

                     switch (sClause.JoinType)
                     {
                         case InnerJoin: JoinString = "INNER JOIN"; break;
                         case OuterJoin: JoinString = "FULL OUTER JOIN"; break;
                         case LeftJoin: JoinString = "LEFT JOIN"; break;
                         case RightJoin: JoinString = "RIGHT JOIN"; break;
                     }
                     JoinString += " " + sClause.ToTable + " ON ";


                     for (JoinClause SubClause : _joins)
                     {
                         if (comptable.equalsIgnoreCase(SubClause.FromTable + SubClause.ToTable))
                         {
                             if (loopcnt == 0)
                             {
                                 JoinString += WhereStatement.CreateComparisonClause(SubClause.FromColumn, SubClause.ComparisonOperator, new SqlLiteral(SubClause.ToColumn), "SqlLiteral", "");
                                 loopcnt += 1;

                             }
                             else
                             {
                                 JoinString += " AND " + WhereStatement.CreateComparisonClause(SubClause.FromColumn, SubClause.ComparisonOperator, new SqlLiteral(SubClause.ToColumn), "SqlLiteral", "");
                             }

                         }
                     }

                     hshTable.put(comptable, comptable);
                     Query += JoinString + "\r" + "        ";
                 }

             }
         }
         // Return the built query
         return Query;
     }
	 
	 public String BuildQueryWhere()
     {
         return (String)this.BuildQueryWhere(false);
     }
	 
	 private Object BuildQueryWhere(boolean buildCommand)
     {
         String Query = "";

         // Output where statement
         if (_whereStatement.getClauseLevels() > 0)
         {
             if (buildCommand)
                 Query += "WHERE" + "  " + _whereStatement.BuildWhereStatement();
             else
                 Query += "WHERE" +  "  " + _whereStatement.BuildWhereStatement();
         }

         
             // Return the built query
     	return Query;
        
     }
	 
	 public String BuildQueryGroupBy()
     {
         return (String)this.BuildQueryGroupBy(false);
     }
	 
	 private Object BuildQueryGroupBy(boolean buildCommand)
     {
		 String Query = "";

         // Output GroupBy statement
         if (_groupByColumns.size() > 0)
         {
             boolean bFirst = false;

             Query += "GROUP BY ";
             for (String Column : _groupByColumns)
             {
                 if (!bFirst)
                 {
                     Query = Query + "\t" + Column + ',';
                     bFirst = true;
                 }
                 else
                 {
                     Query = Query + '\r' + "\t\t" + Column + ',';
                 }
             }
             Query = Query.replaceAll("[,]+$", "");
             Query += ' ';
         }
         return Query;
         
     }
	 
	 public String BuildQueryGroupByRollup()
     {
         return (String)this.BuildQueryGroupByRollup(false);
     }
	 
	 private Object BuildQueryGroupByRollup(boolean buildCommand)
     {
		 String Query = "";

         // Output GroupBy statement
         if (_groupByColumns.size() > 0)
         {
             boolean bFirst = false;

             Query += "GROUP BY ROLLUP (";
             for (String Column : _groupByColumns)
             {
                 if (!bFirst)
                 {
                     Query = Query + "\t" + Column + ',';
                     bFirst = true;
                 }
                 else
                 {
                     Query = Query + '\r' + "\t\t" + Column + ',';
                 }
             }
             Query = Query.replaceAll("[,]+$", "");
             Query += ' ';
         }
         Query += " )";
         return Query;
         
     }
	 
	 public String BuildQueryHaving()
     {
         return (String)this.BuildQueryHaving(false);
     }
	 
	 private Object BuildQueryHaving(boolean buildCommand)
     {
         String Query = "";

         // Output having statement
         if (_havingStatement.getClauseLevels() > 0)
         {
             // Check if a Group By Clause was set
             //if (_groupByColumns.Count == 0)
             //{
             //    throw new Exception("Having statement was set without Group By");
             //}
             if (buildCommand)
                 Query += " HAVING " + _havingStatement.BuildWhereStatement();
             else
                 Query += " HAVING " + _havingStatement.BuildWhereStatement();
         }

         return Query;
         
     }
	 
	 public String BuildQueryOnlyWhere()
     {
         return (String)this.BuildQueryOnlyWhere(false);
     }

     private Object BuildQueryOnlyWhere(boolean buildCommand)
     {
         String Query = "";

         // Output where statement
         if (_whereStatement.getClauseLevels() > 0)
         {
             if (buildCommand)
                 Query += "AND\t\t" + _whereStatement.BuildWhereStatement();
             else
                 Query += "AND\t\t" + _whereStatement.BuildWhereStatement();
         }

       return Query;
         
     }

}
