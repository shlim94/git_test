package com.wise.common.jdbc;

import org.mybatis.spring.SqlSessionTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.support.DaoSupport;

/**
 * @author WISE iTech R&D  DOGFOOT
 * @since 2015.06.08
 * @version 1.0
 * @see
 * 
 * <pre>
 * << 개정이력(Modification Information) >>
 *     수정일                 수정자             수정내용   
 *  ----------    --------    ---------------------------
 *  2015.06.08      DOGFOOT             최초 생성
 * </pre>
 */

public abstract class SqlSessionDaoSupport extends DaoSupport {
    
    protected SqlSessionTemplate sqlSessionTemplate;
    
    protected SqlSessionTemplate sqlSessionTemplate2;
    
    @Autowired(required = false)
    public final void setSqlSessionTemplate(SqlSessionTemplate sqlSessionTemplate) {
        this.sqlSessionTemplate = sqlSessionTemplate;
    }
    
    public SqlSessionTemplate getSqlSession() {
        return this.sqlSessionTemplate;
    }
    
    @Autowired(required = false)
    public final void setSqlSessionTemplate2(SqlSessionTemplate sqlSessionTemplate2) {
        this.sqlSessionTemplate2 = sqlSessionTemplate2;
    }
    
    public SqlSessionTemplate getSqlSession2() {
        return this.sqlSessionTemplate2;
    }

    @Override
    protected void checkDaoConfig() throws IllegalArgumentException {
    }

}
