class SessionsController < ApplicationController
  before_filter :require_logged_in, :only => [:destroy]
  
  def create
    @user = User.find_by_username(params[:username])
    
    if @user.nil?
      redirect_to login_path, :alert => 'We are sorry, but we could not find an account corresponding to that username.'
    else
      @authuser = login(session[:session_id], params[:username], params[:password])
      if @authuser.nil?
        # redirect_to login_path, :alert => 'We could not find an account corresponding to that username and password!'
        redirect_to login_path, :alert => 'Password incorrect. Please try to log in again.'

      else
        session[:user_id] = @authuser.id

        if @authuser.is_admin?
          redirect_to users_path(session[:session_secret])
        else
          redirect_to user_path(session[:session_secret], @authuser)
        end
      end
    end
    
    

  end
  
  def destroy
    session[:user_id] = nil
    redirect_to store_path, :notice => 'You were successfully logged out!'
  end
  
  def change_level
    session[:level] = params[:level].to_i
    redirect_to :back
  end
  
  def reset_database
    DB::reset(session[:session_id])
    reset_session
    redirect_to store_path, :notice => 'Database was reset!'
  end
end